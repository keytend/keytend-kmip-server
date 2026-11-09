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

//! Security regression tests: bounded transparent RSA/DSA import work,
//! administrator-only System Objects without identity reuse, ticket
//! revocation, CA Usage Limits in Certify, Certify under Undo, scrypt outside
//! the engine lock and the asynchronous queue. Each test reproduces a proof
//! of concept and failed before the fix.
use keytend_kmip_server::{
    credentials::{self, PasswordVerifier, PolicyUser},
    protocol::{Engine, Version},
    store::{Store, now},
    tags::*,
    ttlv::{Node, Value},
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder, X509Req, X509ReqBuilder,
        extension::{BasicConstraints, KeyUsage},
    },
};
use std::time::{Duration, Instant};

const V21: Version = Version(2, 1);
const V3: Version = Version(3, 0);

struct Fixture {
    dir: tempfile::TempDir,
    e: Engine,
}
fn engine(dir: &tempfile::TempDir, users: Vec<PolicyUser>) -> anyhow::Result<Engine> {
    let store = Store::open(&dir.path().join("keys.sqlite"), &dir.path().join("master"))?;
    let mut e = Engine::new(store, true);
    e.add_policy_users("alice", users)?;
    Ok(e)
}
fn policy_user(name: &str, password: &[u8], administrator: bool) -> PolicyUser {
    PolicyUser {
        username: name.into(),
        password_scrypt: PasswordVerifier::new(password).unwrap(),
        administrator,
        hashed_password: None,
        one_time_password: None,
    }
}
fn admin_users() -> Vec<PolicyUser> {
    vec![
        policy_user("administrator", b"password", true),
        policy_user("operator", b"operator", false),
    ]
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [7; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let e = engine(&dir, admin_users()).unwrap();
        Self { dir, e }
    }
    fn send(&mut self, owner: &str, request: &Node) -> Node {
        self.e.process(owner, request).unwrap()
    }
    fn call(&mut self, v: Version, auth: Option<Node>, op: u32, p: Vec<Node>) -> Node {
        self.send("alice", &request(v, auth, vec![], vec![(op, p)]))
    }
}
fn request(v: Version, auth: Option<Node>, extra: Vec<Node>, items: Vec<(u32, Vec<Node>)>) -> Node {
    let mut header = vec![v.node()];
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, items.len() as i32));
    }
    header.extend(extra);
    header.extend(auth);
    let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
    let many = items.len() > 1;
    fields.extend(items.into_iter().enumerate().map(|(i, (op, p))| {
        let mut item = vec![Node::enumeration(OPERATION, op)];
        if many && v.0 < 3 {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8]));
        }
        item.push(Node::structure(REQUEST_PAYLOAD, p));
        Node::structure(BATCH_ITEM, item)
    }));
    Node::structure(REQUEST_MESSAGE, fields)
}
fn continuation(option: u32) -> Vec<Node> {
    vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, option)]
}
fn credential(kind: u32, value: Vec<Node>) -> Node {
    Node::structure(
        CREDENTIAL,
        vec![
            Node::enumeration(CREDENTIAL_TYPE, kind),
            Node::structure(CREDENTIAL_VALUE, value),
        ],
    )
}
fn password(user: &str, pw: &str) -> Node {
    credential(
        1,
        vec![Node::text(USERNAME, user), Node::text(PASSWORD, pw)],
    )
}
fn auth(credentials: Vec<Node>) -> Option<Node> {
    Some(Node::structure(AUTHENTICATION, credentials))
}
fn as_user(user: &str, pw: &str) -> Option<Node> {
    auth(vec![password(user, pw)])
}
fn admin() -> Option<Node> {
    as_user("administrator", "password")
}
fn items(r: &Node) -> Vec<&Node> {
    r.all(BATCH_ITEM).collect()
}
fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
/// Result Reason of the first item, or 0 on success.
fn reason(r: &Node) -> u32 {
    let item = items(r)[0];
    if status(item) == 0 {
        0
    } else {
        item.required(RESULT_REASON).unwrap().number().unwrap()
    }
}
fn payload(r: &Node) -> &Node {
    let item = items(r)[0];
    assert_eq!(status(item), 0, "{}", serde_json::to_string(r).unwrap());
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn uid(r: &Node) -> String {
    payload(r)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn id_node(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}

// ---- 1. Transparent RSA/DSA import work -------------------------------

/// Positive two's complement Big Integer, padded to a multiple of 8 bytes.
fn big(tag: u32, magnitude: &[u8]) -> Node {
    let mut b = magnitude.to_vec();
    while !b.len().is_multiple_of(8) || b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    Node {
        tag,
        value: Value::BigInteger(b),
    }
}
fn private_key(format: u32, bits: i32, material: Node) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 4),
        Node::structure(
            ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1),
            ],
        ),
        Node::structure(
            PRIVATE_KEY,
            vec![Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, format),
                    Node::structure(KEY_VALUE, vec![material]),
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, bits),
                ],
            )],
        ),
    ]
}
fn transparent_rsa(k: &Rsa<Private>) -> Vec<Node> {
    let fields = vec![
        big(MODULUS, &k.n().to_vec()),
        big(PRIVATE_EXPONENT, &k.d().to_vec()),
        big(PUBLIC_EXPONENT, &k.e().to_vec()),
        big(P, &k.p().unwrap().to_vec()),
        big(Q, &k.q().unwrap().to_vec()),
    ];
    private_key(
        10,
        k.size() as i32 * 8,
        Node::structure(KEY_MATERIAL, fields),
    )
}

#[test]
fn hostile_transparent_rsa_components_are_rejected_quickly() {
    let mut f = Fixture::new();
    // The attack input: random odd 8192-bit modulus, E = N-2, random D.
    // It used to run factor recovery over 99 bases (about 11 s per item).
    let mut n = vec![0u8; 1024];
    openssl::rand::rand_bytes(&mut n).unwrap();
    n[0] = 0xc0 | (n[0] & 0x3f);
    n[1023] |= 1;
    let mut e = BigNum::from_slice(&n).unwrap();
    e.sub_word(2).unwrap();
    let mut d = vec![0u8; 1024];
    openssl::rand::rand_bytes(&mut d).unwrap();
    d[0] = 0x40 | (d[0] & 0x3f);
    // Odd, so D*E-1 is even and factor recovery is attempted.
    d[1023] |= 1;
    let material = |n: &[u8], e: &[u8], d: &[u8]| {
        Node::structure(
            KEY_MATERIAL,
            vec![
                big(MODULUS, n),
                big(PRIVATE_EXPONENT, d),
                big(PUBLIC_EXPONENT, e),
            ],
        )
    };
    let start = Instant::now();
    let r = f.call(
        V21,
        None,
        3,
        private_key(10, 8192, material(&n, &e.to_vec(), &d)),
    );
    assert_eq!(reason(&r), 7);
    // A random 4096-bit modulus with a standard exponent: one exponentiation
    // shows that D cannot belong to N, before any factor search.
    let mut n = vec![0u8; 512];
    openssl::rand::rand_bytes(&mut n).unwrap();
    n[0] |= 0x80;
    n[511] |= 1;
    let mut d = vec![0u8; 512];
    openssl::rand::rand_bytes(&mut d).unwrap();
    d[0] &= 0x7f;
    d[511] |= 1;
    let r = f.call(
        V21,
        None,
        3,
        private_key(10, 4096, material(&n, &[1, 0, 1], &d)),
    );
    assert_eq!(reason(&r), 7);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "hostile components took {:?}",
        start.elapsed()
    );
}

#[test]
fn costly_key_validations_are_bounded_per_batch() {
    let mut f = Fixture::new();
    let k = Rsa::generate(1024).unwrap();
    // Six transparent private keys in one Continue batch: the first four are
    // validated, the rest get Server Limit Exceeded, like RSA generation.
    let r = f.send(
        "alice",
        &request(
            V21,
            None,
            continuation(1),
            (0..6).map(|_| (3, transparent_rsa(&k))).collect(),
        ),
    );
    let got: Vec<u32> = items(&r)
        .iter()
        .map(|i| {
            if status(i) == 0 {
                0
            } else {
                i.required(RESULT_REASON).unwrap().number().unwrap()
            }
        })
        .collect();
    assert_eq!(got, [0, 0, 0, 0, 0x3a, 0x3a]);
    // The bound is per batch: the next message validates again.
    assert_eq!(reason(&f.call(V21, None, 3, transparent_rsa(&k))), 0);
}

#[test]
fn rsa_size_and_exponent_bounds_are_shared_by_every_import_form() {
    let mut f = Fixture::new();
    // 512-bit RSA was accepted transparently and in PKCS#1; both are refused.
    let small = Rsa::generate(512).unwrap();
    assert_eq!(reason(&f.call(V21, None, 3, transparent_rsa(&small))), 7);
    let pkcs1 = |k: &Rsa<Private>| {
        private_key(
            3,
            k.size() as i32 * 8,
            Node::bytes(KEY_MATERIAL, k.private_key_to_der().unwrap()),
        )
    };
    assert_eq!(reason(&f.call(V21, None, 3, pkcs1(&small))), 7);
    // 1024 bits, the smallest size the profile test cases register, stays.
    let k = Rsa::generate(1024).unwrap();
    assert_eq!(reason(&f.call(V21, None, 3, pkcs1(&k))), 0);
    assert_eq!(reason(&f.call(V21, None, 3, transparent_rsa(&k))), 0);
    // A public exponent of 2^256 + 1 is refused in PKCS#1 form as well.
    let mut e = BigNum::new().unwrap();
    e.set_bit(256).unwrap();
    e.add_word(1).unwrap();
    let public = Rsa::from_public_components(k.n().to_owned().unwrap(), e).unwrap();
    let r = f.call(
        V21,
        None,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 3),
            Node::structure(
                ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2),
                ],
            ),
            Node::structure(
                PUBLIC_KEY,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 3),
                        Node::structure(
                            KEY_VALUE,
                            vec![Node::bytes(
                                KEY_MATERIAL,
                                public.public_key_to_der_pkcs1().unwrap(),
                            )],
                        ),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 1024),
                    ],
                )],
            ),
        ],
    );
    assert_eq!(reason(&r), 7);
}

#[test]
fn oversized_dsa_domains_are_refused_before_primality_tests() {
    // The attack input: a 4096-bit prime P with an unrelated Q. P used to
    // be tested for primality (64 rounds) before the size and Q | P-1 checks.
    let mut p = BigNum::new().unwrap();
    p.generate_prime(4096, false, None, None).unwrap();
    let mut q = BigNum::new().unwrap();
    q.generate_prime(256, false, None, None).unwrap();
    let dsa = |p: &BigNum, q: &BigNum| {
        let start = Instant::now();
        let r = keytend_kmip_server::crypto::transparent::dsa_public(
            BigNum::from_slice(&p.to_vec()).unwrap(),
            BigNum::from_slice(&q.to_vec()).unwrap(),
            BigNum::from_u32(2).unwrap(),
            BigNum::from_u32(3).unwrap(),
        );
        assert!(r.is_err());
        start.elapsed()
    };
    let elapsed = dsa(&p, &q);
    assert!(
        elapsed < Duration::from_millis(200),
        "4096-bit P: {elapsed:?}"
    );
    // A 3072-bit prime P (an accepted size) with Q not dividing P-1.
    let mut p = BigNum::new().unwrap();
    p.generate_prime(3072, false, None, None).unwrap();
    let elapsed = dsa(&p, &q);
    assert!(
        elapsed < Duration::from_millis(200),
        "Q | P-1 must be checked before P's primality ({elapsed:?})"
    );
}

// ---- 2/3. System Objects, identity reuse and tickets --------------------

fn create_credential(f: &mut Fixture, a: Option<Node>, pw: &str) -> Node {
    f.call(
        V3,
        a,
        63,
        vec![
            Node::enumeration(CREDENTIAL_TYPE, 7),
            Node::structure(ATTRIBUTES, vec![]),
            Node::structure(PASSWORD_CREDENTIAL, vec![Node::text(PASSWORD, pw)]),
        ],
    )
}
fn create_user(f: &mut Fixture, a: Option<Node>, name: &str, links: &[&str]) -> Node {
    let mut attrs = vec![Node::text(NAME, name)];
    attrs.extend(links.iter().map(|id| Node::reference(CREDENTIAL_LINK, *id)));
    f.call(V3, a, 62, vec![Node::structure(ATTRIBUTES, attrs)])
}
/// A System User with one password credential, created by the administrator.
fn make_user(f: &mut Fixture, name: &str, pw: &str) -> (String, String) {
    let credential = uid(&create_credential(f, admin(), pw));
    let user = uid(&create_user(f, admin(), name, &[&credential]));
    (user, credential)
}
fn obliterate(f: &mut Fixture, a: Option<Node>, id: &str) -> Node {
    f.call(V3, a, 61, vec![Node::identifier(UNIQUE_IDENTIFIER, id)])
}
fn create_group(f: &mut Fixture, a: Option<Node>, name: &str) -> Node {
    f.call(
        V3,
        a,
        60,
        vec![Node::structure(ATTRIBUTES, vec![Node::text(NAME, name)])],
    )
}
fn secret() -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 7),
        Node::structure(ATTRIBUTES, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 4)]),
        Node::structure(
            SECRET_DATA,
            vec![
                Node::enumeration(SECRET_DATA_TYPE, 1),
                Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 1),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, [42; 16])]),
                    ],
                ),
            ],
        ),
    ]
}

#[test]
fn only_administrators_create_or_obliterate_system_objects() {
    let mut f = Fixture::new();
    let (_, mallory_credential) = make_user(&mut f, "mallory", "mallorypw");
    let mallory = || as_user("mallory", "mallorypw");
    let operator = || as_user("operator", "operator");
    // A verified System User or a users-file user without the flag is
    // refused (Permission Denied) for every System Object operation.
    for a in [mallory(), operator()] {
        assert_eq!(reason(&create_credential(&mut f, a.clone(), "x")), 12);
        assert_eq!(
            reason(&create_user(
                &mut f,
                a.clone(),
                "eve",
                &[&mallory_credential]
            )),
            12
        );
        assert_eq!(reason(&create_group(&mut f, a.clone(), "g")), 12);
        assert_eq!(reason(&obliterate(&mut f, a, &mallory_credential)), 12);
    }
    // A ticket of a System User does not make it an administrator either.
    let r = f.call(V3, mallory(), 45, vec![]);
    let ticket = payload(&r).required(TICKET).unwrap().clone();
    assert_eq!(
        reason(&create_group(
            &mut f,
            auth(vec![credential(6, vec![ticket])]),
            "g"
        )),
        12
    );
    // The administrator may, also through its Login ticket.
    let r = f.call(V3, admin(), 45, vec![]);
    let ticket = payload(&r).required(TICKET).unwrap().clone();
    assert_eq!(
        reason(&create_group(
            &mut f,
            auth(vec![credential(6, vec![ticket])]),
            "g"
        )),
        0
    );
    // One password credential per user: a second one is refused.
    let second = uid(&create_credential(&mut f, admin(), "second"));
    assert_eq!(
        reason(&create_user(
            &mut f,
            admin(),
            "two",
            &[&mallory_credential, &second]
        )),
        0x3a
    );
}

#[test]
fn obliterated_usernames_are_never_reissued() {
    // The takeover: eve owns a key under credential identity, is
    // off-boarded, and "eve" is created again with another password.
    let mut f = Fixture::new();
    f.e.use_credential_identity("alice");
    let (eve_user, eve_credential) = make_user(&mut f, "eve", "evepw");
    let r = f.call(V21, as_user("eve", "evepw"), 3, secret());
    let key = uid(&r);
    for id in [&eve_user, &eve_credential] {
        assert_eq!(reason(&obliterate(&mut f, admin(), id)), 0);
    }
    assert_eq!(reason(&f.call(V21, as_user("eve", "evepw"), 24, vec![])), 3);
    // Not even the administrator can issue the retired name again.
    let other = uid(&create_credential(&mut f, admin(), "mallory-chosen"));
    assert_eq!(
        reason(&create_user(&mut f, admin(), "eve", &[&other])),
        0x35
    );
    let r = f.call(
        V21,
        as_user("eve", "mallory-chosen"),
        10,
        vec![Node::text(UNIQUE_IDENTIFIER, &key)],
    );
    assert_eq!(reason(&r), 3);
    // The retired-name record is not a visible or removable object.
    assert_ne!(reason(&obliterate(&mut f, admin(), &eve_user)), 0);
    // A users file naming the retired user is refused at startup.
    drop(f.e);
    let mut users = admin_users();
    users.push(policy_user("eve", b"operator-chosen", false));
    assert!(engine(&f.dir, users).is_err());
}

#[test]
fn users_file_and_system_users_never_share_a_name() {
    // The squat: a System User "bob" exists before the operator
    // provisions bob in the users file. Startup now refuses that file.
    let mut f = Fixture::new();
    f.e.use_credential_identity("alice");
    make_user(&mut f, "bob", "squat");
    drop(f.e);
    let mut users = admin_users();
    users.push(policy_user("bob", b"bobs-real-pw", false));
    let error = engine(&f.dir, users).err().expect("startup must refuse");
    assert!(error.to_string().contains("bob"), "{error}");
    // Creation refuses a users-file name (unchanged behavior).
    f.e = engine(&f.dir, admin_users()).unwrap();
    let c = uid(&create_credential(&mut f, admin(), "pw"));
    assert_eq!(
        reason(&create_user(&mut f, admin(), "operator", &[&c])),
        0x35
    );
}

#[test]
fn tickets_die_with_their_user_or_credential() {
    for obliterated in ["user", "credential"] {
        let mut f = Fixture::new();
        let (user, credential_id) = make_user(&mut f, "eve", "evepw");
        let r = f.call(V3, as_user("eve", "evepw"), 45, vec![]);
        let ticket = payload(&r).required(TICKET).unwrap().clone();
        let by_ticket = || auth(vec![credential(6, vec![ticket.clone()])]);
        assert_eq!(reason(&f.call(V3, by_ticket(), 24, vec![])), 0);
        let target = if obliterated == "user" {
            &user
        } else {
            &credential_id
        };
        assert_eq!(reason(&obliterate(&mut f, admin(), target)), 0);
        assert_eq!(
            reason(&f.call(V3, by_ticket(), 24, vec![])),
            3,
            "ticket after obliterating its {obliterated}"
        );
    }
    // A ticket stays valid while the user and its credential stay.
    let mut f = Fixture::new();
    make_user(&mut f, "eve", "evepw");
    let (other, _) = make_user(&mut f, "zed", "zedpw");
    let r = f.call(V3, as_user("eve", "evepw"), 45, vec![]);
    let ticket = payload(&r).required(TICKET).unwrap().clone();
    assert_eq!(reason(&obliterate(&mut f, admin(), &other)), 0);
    assert_eq!(
        reason(&f.call(V3, auth(vec![credential(6, vec![ticket])]), 24, vec![])),
        0
    );
}

// ---- 4/5. Certify ---------------------------------------------------------

fn rsa() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}
fn register_key(
    f: &mut Fixture,
    key: &PKey<Private>,
    private: bool,
    usage: i32,
    mut extra: Vec<Node>,
) -> String {
    let (kind, tag, der) = if private {
        (
            4,
            PRIVATE_KEY,
            key.rsa().unwrap().private_key_to_der().unwrap(),
        )
    } else {
        (
            3,
            PUBLIC_KEY,
            key.rsa().unwrap().public_key_to_der_pkcs1().unwrap(),
        )
    };
    extra.extend([
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage),
    ]);
    uid(&f.call(
        V21,
        None,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            Node::structure(ATTRIBUTES, extra),
            Node::structure(
                tag,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 3),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, der)]),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                    ],
                )],
            ),
        ],
    ))
}
fn ca_certificate(key: &PKey<Private>) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Test Issuing CA").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(now() - 3600).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(now() + 3 * 365 * 86400).unwrap())
        .unwrap();
    b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    b.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()
            .unwrap(),
    )
    .unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build()
}
/// Certificate -> Public Key Link -> public key -> Private Key Link ->
/// private key (with `limits` attributes), all Active. Returns (CA, private).
fn ca(f: &mut Fixture, limits: Vec<Node>) -> (String, String) {
    let key = rsa();
    let certificate = ca_certificate(&key);
    let private = register_key(f, &key, true, 0x1000 | 1, limits);
    let link = |kind: u32, id: &str| {
        Node::structure(
            LINK,
            vec![
                Node::enumeration(LINK_TYPE, kind),
                Node::text(LINKED_OBJECT_IDENTIFIER, id),
            ],
        )
    };
    let public = register_key(f, &key, false, 2, vec![link(0x103, &private)]);
    let der = certificate.to_der().unwrap();
    let id = uid(&f.call(
        V21,
        None,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 1),
            Node::structure(
                ATTRIBUTES,
                vec![
                    link(0x102, &public),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x1000 | 2),
                ],
            ),
            Node::structure(
                CERTIFICATE,
                vec![
                    Node::enumeration(CERTIFICATE_TYPE, 1),
                    Node::bytes(CERTIFICATE_VALUE, der),
                ],
            ),
        ],
    ));
    for target in [&private, &id] {
        assert_eq!(
            reason(&f.call(V21, None, 18, vec![id_node(V21, target)])),
            0
        );
    }
    (id, private)
}
fn csr(cn: &str) -> X509Req {
    let key = rsa();
    let mut b = X509ReqBuilder::new().unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    b.set_subject_name(&name.build()).unwrap();
    b.set_pubkey(&key).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    b.build()
}
fn certify(ca: &str, cn: &str) -> Vec<Node> {
    vec![
        Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
        Node::bytes(CERTIFICATE_REQUEST_VALUE, csr(cn).to_der().unwrap()),
        Node::structure(
            ATTRIBUTES,
            vec![Node::structure(
                LINK,
                vec![
                    Node::enumeration(LINK_TYPE, 0x101),
                    Node::text(LINKED_OBJECT_IDENTIFIER, ca),
                ],
            )],
        ),
    ]
}

#[test]
fn certify_charges_the_ca_key_usage_limits() {
    let mut f = Fixture::new();
    // The case: a CA key limited to one use issued five
    // certificates. Usage Limits Unit Object (2), total 1.
    let limits = Node::structure(
        USAGE_LIMITS,
        vec![
            Node::long(USAGE_LIMITS_TOTAL, 1),
            Node::enumeration(USAGE_LIMITS_UNIT, 2),
        ],
    );
    let (authority, private) = ca(&mut f, vec![limits]);
    assert_eq!(
        reason(&f.call(V21, None, 6, certify(&authority, "leaf 0"))),
        0
    );
    for i in 1..3 {
        assert_eq!(
            reason(&f.call(V21, None, 6, certify(&authority, &format!("leaf {i}")))),
            12
        );
    }
    let r = f.call(V21, None, 11, vec![id_node(V21, &private)]);
    let limits = payload(&r)
        .required(ATTRIBUTES)
        .unwrap()
        .required(USAGE_LIMITS)
        .unwrap();
    assert!(limits.required(USAGE_LIMITS_COUNT).unwrap().value == Value::LongInteger(0));
    // Byte unit: the TBSCertificate length is charged.
    let limits = Node::structure(
        USAGE_LIMITS,
        vec![
            Node::long(USAGE_LIMITS_TOTAL, 100_000),
            Node::enumeration(USAGE_LIMITS_UNIT, 1),
        ],
    );
    let (authority, private) = ca(&mut f, vec![limits]);
    assert_eq!(
        reason(&f.call(V21, None, 6, certify(&authority, "leaf"))),
        0
    );
    let r = f.call(V21, None, 11, vec![id_node(V21, &private)]);
    let Value::LongInteger(left) = payload(&r)
        .required(ATTRIBUTES)
        .unwrap()
        .required(USAGE_LIMITS)
        .unwrap()
        .required(USAGE_LIMITS_COUNT)
        .unwrap()
        .value
    else {
        panic!("Usage Limits Count")
    };
    assert!((99_000..100_000).contains(&left), "{left}");
}

#[test]
fn certify_is_refused_in_undo_batches() {
    // The batch: Certify, Get by ID Placeholder, then a failing Get
    // under Undo returned a valid CA-signed certificate whose record was
    // rolled back.
    let mut f = Fixture::new();
    let (authority, _) = ca(&mut f, vec![]);
    let r = f.send(
        "alice",
        &request(
            V21,
            None,
            continuation(3),
            vec![
                (6, certify(&authority, "undone leaf")),
                (10, vec![]),
                (10, vec![Node::text(UNIQUE_IDENTIFIER, "does-not-exist")]),
            ],
        ),
    );
    let all = items(&r);
    assert_eq!(all.len(), 1, "{}", serde_json::to_string(&r).unwrap());
    assert_eq!(status(all[0]), 1);
    assert_eq!(all[0].required(RESULT_REASON).unwrap().number().unwrap(), 8);
    assert!(
        !serde_json::to_string(&r)
            .unwrap()
            .contains("CertificateValue")
    );
    // A Continue batch still certifies.
    let r = f.send(
        "alice",
        &request(
            V21,
            None,
            continuation(1),
            vec![(6, certify(&authority, "leaf")), (10, vec![])],
        ),
    );
    assert!(items(&r).iter().all(|i| status(i) == 0));
}

// ---- 6. scrypt and the engine lock ---------------------------------------

#[test]
fn unlisted_certificates_and_userless_principals_cost_no_scrypt() {
    let mut f = Fixture::new();
    let query = || (24, vec![Node::enumeration(QUERY_FUNCTION, 1)]);
    // The request: four password credentials over an unlisted
    // certificate (no permitted operation) used to cost four evaluations.
    let creds = (0..4).map(|i| password(&format!("u{i}"), "x")).collect();
    let before = credentials::derivations();
    let r =
        f.e.process_with_grants(
            "\0unlisted",
            &request(Version(1, 4), auth(creds), vec![], vec![query()]),
            Some(&[]),
            &[],
        )
        .unwrap();
    assert_eq!(reason(&r), 12);
    // A listed principal without users or devices has no username to hide.
    let r = f.send(
        "bob",
        &request(
            V21,
            as_user("administrator", "password"),
            vec![],
            vec![query()],
        ),
    );
    assert_eq!(reason(&r), 3);
    assert_eq!(credentials::derivations(), before);
    // With users, an unknown username still costs one evaluation.
    let r = f.call(V21, as_user("nobody", "x"), 24, vec![]);
    assert_eq!(reason(&r), 3);
    assert_eq!(credentials::derivations(), before + 1);
}

#[test]
fn credential_work_runs_before_the_request_takes_the_lock() {
    let mut f = Fixture::new();
    let (_, _) = make_user(&mut f, "eve", "evepw");
    for (creds, expected) in [
        (vec![password("administrator", "password")], 0),
        (vec![password("eve", "evepw")], 0),
        (vec![password("eve", "wrong")], 3),
        (vec![password("nobody", "x")], 3),
    ] {
        let message = request(V21, auth(creds), vec![], vec![(24, vec![])]);
        let work = f.e.credential_work("alice", &message, Some(&[24]));
        assert!(!work.is_empty());
        let done = work.run();
        let before = credentials::derivations();
        let r = done.scope(|| {
            f.e.process_authorized("alice", &message, Some(&[24]))
                .unwrap()
        });
        assert_eq!(reason(&r), expected);
        assert_eq!(
            credentials::derivations(),
            before,
            "scrypt ran under the lock"
        );
    }
    // No work for an unlisted certificate.
    let message = request(V21, admin(), vec![], vec![(24, vec![])]);
    assert!(
        f.e.credential_work("\0unlisted", &message, Some(&[]))
            .is_empty()
    );
}

// ---- Asynchronous queue --------------------------------------------------

fn mandatory() -> Vec<Node> {
    vec![Node::enumeration(ASYNCHRONOUS_INDICATOR, 1)]
}

#[test]
fn queued_batches_keep_the_verified_identity_not_the_password() {
    let mut f = Fixture::new();
    let r = f.send(
        "alice",
        &request(
            V21,
            as_user("operator", "operator"),
            mandatory(),
            vec![(24, vec![])],
        ),
    );
    assert_eq!(status(items(&r)[0]), 2);
    // Running the batch does not verify a password again: none was kept.
    let before = credentials::derivations();
    assert!(f.e.run_asynchronous());
    assert_eq!(credentials::derivations(), before);
    // The stored identity is re-checked: a System User obliterated before
    // its batch runs fails it with Authentication Not Successful.
    let (eve, _) = make_user(&mut f, "eve", "evepw");
    let r = f.send(
        "alice",
        &request(
            V21,
            as_user("eve", "evepw"),
            mandatory(),
            vec![(24, vec![])],
        ),
    );
    let value = items(&r)[0]
        .required(ASYNCHRONOUS_CORRELATION_VALUE)
        .unwrap()
        .clone();
    assert_eq!(reason(&obliterate(&mut f, admin(), &eve)), 0);
    assert!(f.e.run_asynchronous());
    let r = f.call(V21, None, 26, vec![value]);
    let polled = items(&r)[0];
    assert_eq!(status(polled), 1);
    assert_eq!(polled.required(RESULT_REASON).unwrap().number().unwrap(), 3);
}

#[test]
fn completed_batches_do_not_lock_out_the_queue() {
    // The lock-out: completed batches counted against the limits
    // for ten minutes, so filled queues refused Mandatory requests.
    let mut f = Fixture::new();
    let owners: Vec<String> = (0..5).map(|i| format!("p{i}")).collect();
    for owner in &owners[..4] {
        for _ in 0..8 {
            let r = f.send(owner, &request(V21, None, mandatory(), vec![(24, vec![])]));
            assert_eq!(status(items(&r)[0]), 2);
            assert!(f.e.run_asynchronous());
        }
    }
    // A fifth principal, and each of the first four again, still get in.
    for owner in &owners {
        let r = f.send(owner, &request(V21, None, mandatory(), vec![(24, vec![])]));
        assert_eq!(status(items(&r)[0]), 2, "{owner}");
    }
    // Waiting batches are still bounded per principal.
    for _ in 0..7 {
        let r = f.send("p0", &request(V21, None, mandatory(), vec![(24, vec![])]));
        assert_eq!(status(items(&r)[0]), 2);
    }
    let r = f.send("p0", &request(V21, None, mandatory(), vec![(24, vec![])]));
    assert_eq!(reason(&r), 0x3a);
}
