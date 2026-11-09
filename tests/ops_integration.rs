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

//! Interactions between Login tickets and Delegated Login (tickets.rs),
//! server defaults and constraints (defaults.rs, constraints.rs) and
//! Re-Provision (provisioning.rs). Synthetic `Channel`s stand in for TLS
//! connections: alice has the certificates F and G, bob has B.
#[path = "support/tickets.rs"]
mod support;
use keytend_kmip_server::{
    credentials::{PasswordVerifier, PolicyUser},
    protocol::{Channel, Engine, Lookup, Provisioning, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{
        X509, X509NameBuilder, X509PurposeId, X509Req, X509ReqBuilder, X509StoreContext,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        store::X509StoreBuilder,
    },
};
use std::collections::HashSet;
use support::{
    V3, V21, auth, by_ticket, password, payload, reason, request, right, rights, status, ticket,
    uid,
};

const CREATE: u32 = 1;
const GET: u32 = 10;
const GET_ATTRIBUTES: u32 = 11;
const QUERY: u32 = 24;
const POLL: u32 = 26;
const LOGIN: u32 = 45;
const DELEGATED_LOGIN: u32 = 47;
const RE_PROVISION: u32 = 53;
const SET_DEFAULTS: u32 = 54;
const SET_CONSTRAINTS: u32 = 55;
const GET_CONSTRAINTS: u32 = 56;
const PROCESS: u32 = 58;
const CONSTRAINT_VIOLATION: u32 = 0x4b;
const OBJECT_NOT_FOUND: u32 = 0x37;
const OPS: &[u32] = &[
    1, 2, 3, 8, 10, 11, 18, 20, 24, 26, 45, 46, 47, 53, 54, 55, 56, 58,
];

type Verify = Box<dyn Fn(&X509, &[X509]) -> Result<(), String> + Send + Sync>;

fn rsa(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
}
fn p256() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}
fn name(cn: &str) -> openssl::x509::X509Name {
    let mut n = X509NameBuilder::new().unwrap();
    n.append_entry_by_text("CN", cn).unwrap();
    n.build()
}
fn serial() -> openssl::asn1::Asn1Integer {
    let mut b = BigNum::new().unwrap();
    b.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    b.to_asn1_integer().unwrap()
}
fn certificate(
    issuer: Option<(&X509, &PKey<Private>)>,
    key: &PKey<Private>,
    cn: &str,
    ca: bool,
) -> X509 {
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&serial()).unwrap();
    b.set_subject_name(&name(cn)).unwrap();
    match issuer {
        Some((issuer, _)) => b.set_issuer_name(issuer.subject_name()).unwrap(),
        None => b.set_issuer_name(&name(cn)).unwrap(),
    }
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    if ca {
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    } else {
        b.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        b.append_extension(KeyUsage::new().digital_signature().build().unwrap())
            .unwrap();
        b.append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .dns(&format!("{cn}.example"))
            .build(&b.x509v3_context(issuer.map(|(c, _)| &**c), None))
            .unwrap();
        b.append_extension(san).unwrap();
    }
    let signer: &PKey<Private> = issuer.map_or(key, |(_, k)| k);
    b.sign(signer, MessageDigest::sha256()).unwrap();
    b.build()
}
fn csr(key: &PKey<Private>, cn: &str) -> X509Req {
    let mut b = X509ReqBuilder::new().unwrap();
    b.set_subject_name(&name(cn)).unwrap();
    b.set_pubkey(key).unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build()
}
fn fingerprint(cert: &X509) -> String {
    hex::encode(cert.digest(MessageDigest::sha256()).unwrap())
}
fn verifier(ca: X509) -> Verify {
    let mut b = X509StoreBuilder::new().unwrap();
    b.add_cert(ca).unwrap();
    b.set_purpose(X509PurposeId::SSL_CLIENT).unwrap();
    let store = b.build();
    Box::new(move |leaf: &X509, chain: &[X509]| {
        let mut untrusted = Stack::new().map_err(|e| e.to_string())?;
        for cert in chain {
            untrusted.push(cert.clone()).map_err(|e| e.to_string())?;
        }
        let mut ctx = X509StoreContext::new().map_err(|e| e.to_string())?;
        ctx.init(&store, leaf, &untrusted, |c| {
            Ok(if c.verify_cert()? {
                Ok(())
            } else {
                Err(c.error().to_string())
            })
        })
        .map_err(|e| e.to_string())?
    })
}
fn channel(cert: &X509) -> Channel {
    Channel {
        fingerprint: fingerprint(cert),
        policy_fingerprint: fingerprint(cert),
        certificate: cert.to_der().unwrap(),
        chain: vec![],
    }
}

struct Ix {
    _dir: tempfile::TempDir,
    e: Engine,
    ca: X509,
    ca_key: PKey<Private>,
    /// alice's certificate F and its key; G is alice's second certificate.
    f: X509,
    f_ch: Channel,
    g_ch: Channel,
    b_ch: Channel,
}
impl Ix {
    fn new() -> Self {
        Self::with_key(rsa(2048))
    }
    /// F's key decides the key type a Re-Provision must keep.
    fn with_key(f_key: PKey<Private>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let private = |path: &std::path::Path, bytes: &[u8]| {
            std::fs::write(path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        };
        let master = dir.path().join("master");
        private(&master, &[4; 32]);
        let ca_key = rsa(2048);
        let ca = certificate(None, &ca_key, "provisioning CA", true);
        let f = certificate(Some((&ca, &ca_key)), &f_key, "alice", false);
        let g = certificate(Some((&ca, &ca_key)), &p256(), "alice-admin", false);
        let b = certificate(Some((&ca, &ca_key)), &p256(), "bob", false);
        let ca_path = dir.path().join("ca.pem");
        let key_path = dir.path().join("ca.key");
        std::fs::write(&ca_path, ca.to_pem().unwrap()).unwrap();
        private(&key_path, &ca_key.private_key_to_pem_pkcs8().unwrap());
        let policy = HashSet::from([fingerprint(&f), fingerprint(&g), fingerprint(&b)]);
        let provisioning =
            Provisioning::load(&ca_path, &key_path, verifier(ca.clone()), policy).unwrap();
        let store = Store::open(&dir.path().join("store.sqlite"), &master).unwrap();
        let mut e = Engine::new(store, true).with_provisioning(provisioning);
        e.add_policy_users(
            "alice",
            vec![PolicyUser {
                username: "Fred".into(),
                password_scrypt: PasswordVerifier::new(b"fred").unwrap(),
                administrator: false,
                hashed_password: None,
                one_time_password: None,
            }],
        )
        .unwrap();
        Self {
            _dir: dir,
            e,
            ca,
            ca_key,
            f_ch: channel(&f),
            g_ch: channel(&g),
            b_ch: channel(&b),
            f,
        }
    }
    /// One message on a connection; `auth` is the request header's
    /// Authentication.
    fn on(
        &mut self,
        ch: &Channel,
        owner: &str,
        v: Version,
        header: Vec<Node>,
        auth: Option<Node>,
        items: Vec<(u32, Vec<Node>)>,
    ) -> Vec<Node> {
        let msg = request(v, header, auth, items);
        self.e
            .with_channel(ch, |e| e.process_with_grants(owner, &msg, Some(OPS), &[]))
            .unwrap()
            .all(BATCH_ITEM)
            .cloned()
            .collect()
    }
    fn one(
        &mut self,
        ch: &Channel,
        owner: &str,
        v: Version,
        auth: Option<Node>,
        op: u32,
        p: Vec<Node>,
    ) -> Node {
        self.on(ch, owner, v, vec![], auth, vec![(op, p)]).remove(0)
    }
    fn f_state(&self) -> Lookup {
        self.e.provisioned_lookup(&self.f_ch.fingerprint).unwrap()
    }
    /// A 2.1 Login ticket of alice obtained on `ch`.
    fn login(&mut self, ch: &Channel) -> Node {
        let ch = ch.clone();
        ticket(&self.one(&ch, "alice", V21, None, LOGIN, vec![]))
    }
    /// A 2.1 delegated ticket of alice obtained on `ch`.
    fn delegate(&mut self, ch: &Channel, r: Vec<Node>) -> Node {
        let ch = ch.clone();
        ticket(&self.one(&ch, "alice", V21, None, DELEGATED_LOGIN, rights(r)))
    }
    /// The CSR form, with the certificate fetched in the same message.
    fn re_provision_csr(&mut self, v: Version, auth: Option<Node>) -> Vec<Node> {
        let request = csr(&rsa(2048), "anything");
        let field = Node::structure(
            CERTIFICATE_REQUEST,
            vec![
                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                Node::bytes(CERTIFICATE_REQUEST_VALUE, request.to_der().unwrap()),
            ],
        );
        let ch = self.f_ch.clone();
        self.on(
            &ch,
            "alice",
            v,
            vec![],
            auth,
            vec![(RE_PROVISION, vec![field]), (GET, placeholder(v))],
        )
    }
    /// The no-parameter form: the key and its certificate's identifier.
    fn re_provision_generated(&mut self, v: Version) -> Vec<Node> {
        let ch = self.f_ch.clone();
        self.on(
            &ch,
            "alice",
            v,
            vec![],
            None,
            vec![
                (RE_PROVISION, vec![]),
                (GET, placeholder(v)),
                (GET_ATTRIBUTES, link_reference(v)),
            ],
        )
    }
    /// The certificate form: adopt a certificate of F's identity.
    fn re_provision_adopt(&mut self, v: Version) -> Vec<Node> {
        let key = match self.f.public_key().unwrap().id() {
            Id::EC => p256(),
            _ => rsa(2048),
        };
        let adopted = certificate(Some((&self.ca, &self.ca_key)), &key, "alice", false);
        let field = Node::structure(
            CERTIFICATE,
            vec![
                Node::enumeration(CERTIFICATE_TYPE, 1),
                Node::bytes(CERTIFICATE_VALUE, adopted.to_der().unwrap()),
            ],
        );
        let ch = self.f_ch.clone();
        self.on(
            &ch,
            "alice",
            v,
            vec![],
            None,
            vec![(RE_PROVISION, vec![field])],
        )
    }
}
fn placeholder(v: Version) -> Vec<Node> {
    if v.0 >= 3 {
        vec![Node::enumeration(UNIQUE_IDENTIFIER, 1)]
    } else {
        vec![]
    }
}
fn link_reference(v: Version) -> Vec<Node> {
    let mut p = placeholder(v);
    p.push(Node::enumeration(
        ATTRIBUTE_REFERENCE,
        if v.0 >= 3 {
            PKCS_12_CERTIFICATE_LINK
        } else {
            LINK
        },
    ));
    p
}
/// The certificate identifier from the Get Attributes of a generated key.
fn certificate_link(v: Version, item: &Node) -> String {
    let attrs = payload(item).required(ATTRIBUTES).unwrap();
    if v.0 >= 3 {
        return attrs
            .required(PKCS_12_CERTIFICATE_LINK)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
    }
    attrs
        .all(LINK)
        .find(|l| l.get(LINK_TYPE).unwrap().number().unwrap() == 0x10c)
        .unwrap()
        .required(LINKED_OBJECT_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn identifier(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn certificate_value(item: &Node) -> X509 {
    let der = payload(item)
        .required(CERTIFICATE)
        .unwrap()
        .required(CERTIFICATE_VALUE)
        .unwrap()
        .byte_string()
        .unwrap();
    X509::from_der(der).unwrap()
}
fn aes(v: Version, bits: i32) -> Vec<Node> {
    let _ = v;
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::structure(
            ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, bits),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            ],
        ),
    ]
}
fn constraints(entries: Vec<(u32, Node)>) -> Vec<Node> {
    vec![Node::structure(
        CONSTRAINTS,
        entries
            .into_iter()
            .map(|(kind, attribute)| {
                Node::structure(
                    CONSTRAINT,
                    vec![
                        Node::structure(OBJECT_TYPES, vec![Node::enumeration(OBJECT_TYPE, kind)]),
                        Node::structure(ATTRIBUTES, vec![attribute]),
                    ],
                )
            })
            .collect(),
    )]
}
fn all_ok(items: &[Node]) {
    for item in items {
        payload(item);
    }
}

#[test]
fn re_provision_is_refused_under_any_ticket() {
    let mut x = Ix::new();
    let f = x.f_ch.clone();
    let login = x.login(&f);
    assert_eq!(reason(&x.re_provision_csr(V21, by_ticket(&login))[0]), 12);
    let delegated = x.delegate(&f, vec![right(&[], vec![], None)]);
    assert_eq!(
        reason(&x.re_provision_csr(V21, by_ticket(&delegated))[0]),
        12
    );
    // A delegated ticket may not even name Re-Provision.
    let r = x.one(
        &f,
        "alice",
        V21,
        None,
        DELEGATED_LOGIN,
        rights(vec![right(&[RE_PROVISION], vec![], None)]),
    );
    assert_eq!(reason(&r), 12);
    assert_eq!(x.f_state(), Lookup::Unknown);
}

#[test]
fn tickets_obtained_over_the_replaced_certificate_stop_at_commit() {
    let mut x = Ix::new();
    let (f, g, b) = (x.f_ch.clone(), x.g_ch.clone(), x.b_ch.clone());
    let on_f = x.login(&f);
    let on_g = x.login(&g);
    let delegated = x.delegate(&f, vec![right(&[QUERY], vec![], None)]);
    // A failed Re-Provision message (the certificate is not fetched in it)
    // changes nothing, tickets included.
    let request = csr(&rsa(2048), "alice");
    let field = Node::structure(
        CERTIFICATE_REQUEST,
        vec![
            Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
            Node::bytes(CERTIFICATE_REQUEST_VALUE, request.to_der().unwrap()),
        ],
    );
    let r = x.one(&f, "alice", V21, None, RE_PROVISION, vec![field]);
    assert_eq!(reason(&r), 7);
    payload(&x.one(&f, "alice", V21, by_ticket(&on_f), QUERY, vec![]));
    // A queued batch authenticated by the F ticket.
    let queued = x.on(
        &f,
        "alice",
        V21,
        support::asynchronous(support::MANDATORY),
        by_ticket(&on_f),
        vec![(CREATE, aes(V21, 256))],
    );
    assert_eq!(status(&queued[0]), 2);
    let acv = queued[0]
        .required(ASYNCHRONOUS_CORRELATION_VALUE)
        .unwrap()
        .clone();
    all_ok(&x.re_provision_csr(V21, None));
    assert_eq!(x.f_state(), Lookup::Retired);
    // Tickets obtained over F are gone; G's ticket of the same principal
    // stays.
    assert_eq!(
        reason(&x.one(&f, "alice", V21, by_ticket(&on_f), QUERY, vec![])),
        3
    );
    assert_eq!(
        reason(&x.one(&b, "bob", V21, by_ticket(&delegated), QUERY, vec![])),
        3
    );
    payload(&x.one(&g, "alice", V21, by_ticket(&on_g), QUERY, vec![]));
    // The queued batch no longer runs.
    x.one(&f, "alice", V21, None, PROCESS, vec![acv.clone()]);
    assert_eq!(reason(&x.one(&f, "alice", V21, None, POLL, vec![acv])), 3);
}

#[test]
fn a_retired_open_connection_cannot_obtain_tickets() {
    let mut x = Ix::new();
    let issued = x.re_provision_csr(V21, None);
    all_ok(&issued);
    let new = channel(&certificate_value(&issued[1]));
    let f = x.f_ch.clone();
    for (op, p) in [
        (LOGIN, vec![]),
        (DELEGATED_LOGIN, rights(vec![right(&[QUERY], vec![], None)])),
    ] {
        assert_eq!(reason(&x.one(&f, "alice", V21, None, op, p.clone())), 12);
        ticket(&x.one(&new, "alice", V21, None, op, p));
    }
    // A password does not change that the certificate was retired.
    let fred = auth(vec![password("Fred", "fred")]);
    assert_eq!(reason(&x.one(&f, "alice", V21, fred, LOGIN, vec![])), 12);
    // The open connection keeps its other work.
    uid(&x.one(&f, "alice", V21, None, CREATE, aes(V21, 256)));
}

#[test]
fn server_wide_operations_are_never_delegated() {
    let mut x = Ix::new();
    let f = x.f_ch.clone();
    let b = x.b_ch.clone();
    for op in [RE_PROVISION, SET_DEFAULTS, SET_CONSTRAINTS] {
        let r = x.one(
            &f,
            "alice",
            V21,
            None,
            DELEGATED_LOGIN,
            rights(vec![right(&[op], vec![], None)]),
        );
        assert_eq!(reason(&r), 12, "operation {op}");
    }
    // A Right without Operations still excludes them.
    let delegated = x.delegate(&f, vec![right(&[], vec![], None)]);
    for (op, p) in [
        (SET_DEFAULTS, vec![]),
        (SET_CONSTRAINTS, constraints(vec![])),
        (RE_PROVISION, vec![]),
    ] {
        let r = x.one(&b, "bob", V21, by_ticket(&delegated), op, p);
        assert_eq!(reason(&r), 12, "operation {op}");
    }
    assert_eq!(x.f_state(), Lookup::Unknown);
}

#[test]
fn server_constraints_bind_delegates_and_other_principals_across_editions() {
    let mut x = Ix::new();
    let (f, b) = (x.f_ch.clone(), x.b_ch.clone());
    let set = constraints(vec![(2, Node::int(CRYPTOGRAPHIC_LENGTH, 256))]);
    payload(&x.one(&f, "alice", V21, None, SET_CONSTRAINTS, set));
    // bob in 3.0, under the server set alice wrote in 2.1.
    let r = x.one(&b, "bob", V3, None, CREATE, aes(V3, 128));
    assert_eq!(reason(&r), CONSTRAINT_VIOLATION);
    uid(&x.one(&b, "bob", V3, None, CREATE, aes(V3, 256)));
    // 3.0 Get Constraints is bob's own (empty) set; 2.1 reads the server set.
    let own = x.one(&b, "bob", V3, None, GET_CONSTRAINTS, vec![]);
    assert!(
        payload(&own)
            .required(CONSTRAINTS)
            .unwrap()
            .children()
            .unwrap()
            .is_empty()
    );
    let server = x.one(&b, "bob", V21, None, GET_CONSTRAINTS, vec![]);
    assert_eq!(
        payload(&server)
            .required(CONSTRAINTS)
            .unwrap()
            .all(CONSTRAINT)
            .count(),
        1
    );
    // A delegate creates as the delegator, under the same server set.
    let delegated = x.delegate(&f, vec![right(&[CREATE], vec![], None)]);
    let r = x.one(&b, "bob", V21, by_ticket(&delegated), CREATE, aes(V21, 128));
    assert_eq!(reason(&r), CONSTRAINT_VIOLATION);
    let id = uid(&x.one(&b, "bob", V21, by_ticket(&delegated), CREATE, aes(V21, 256)));
    assert!(x.e.store.get("alice", &id).unwrap().is_some());
}

#[test]
fn re_provision_objects_are_exempt_from_server_and_owner_constraints() {
    for form in ["csr", "generated", "adopted"] {
        let mut x = Ix::new();
        let f = x.f_ch.clone();
        // Every new Private Key and Certificate would violate these.
        let set = || {
            constraints(vec![
                (4, Node::boolean(SENSITIVE, true)),
                (1, Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x0200_0000)),
            ])
        };
        payload(&x.one(&f, "alice", V21, None, SET_CONSTRAINTS, set()));
        payload(&x.one(&f, "alice", V3, None, SET_CONSTRAINTS, set()));
        // They bite an ordinary key pair.
        let pair = vec![
            Node::structure(
                COMMON_ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
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
        ];
        let r = x.one(&f, "alice", V21, None, 2, pair);
        assert_eq!(reason(&r), CONSTRAINT_VIOLATION);
        for v in [V21, V3] {
            let r = match form {
                "csr" => x.re_provision_csr(v, None),
                "generated" => x.re_provision_generated(v),
                _ => x.re_provision_adopt(v),
            };
            all_ok(&r);
            assert_eq!(x.f_state(), Lookup::Retired, "{form} {v:?}");
            // One Re-Provision per certificate: start over for 3.0.
            x = Ix::new();
            let f = x.f_ch.clone();
            payload(&x.one(&f, "alice", V21, None, SET_CONSTRAINTS, set()));
            payload(&x.one(&f, "alice", V3, None, SET_CONSTRAINTS, set()));
        }
    }
}

/// The 3.0 owner set on its own: it refuses an ordinary key pair but not
/// Re-Provision's objects.
#[test]
fn owner_constraints_alone_do_not_block_re_provision() {
    let mut x = Ix::new();
    let f = x.f_ch.clone();
    let set = constraints(vec![(4, Node::boolean(SENSITIVE, true))]);
    payload(&x.one(&f, "alice", V3, None, SET_CONSTRAINTS, set));
    let pair = vec![
        Node::structure(
            COMMON_ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
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
    ];
    // The 2.1 server set is empty: the same pair passes in 2.1.
    payload(&x.one(&f, "alice", V21, None, 2, pair.clone()));
    let r = x.one(&f, "alice", V3, None, 2, pair);
    assert_eq!(reason(&r), CONSTRAINT_VIOLATION);
    all_ok(&x.re_provision_generated(V3));
    assert_eq!(x.f_state(), Lookup::Retired);
}

#[test]
fn server_defaults_do_not_change_the_generated_key() {
    for (f_key, expected) in [(p256(), Id::EC), (rsa(2048), Id::RSA)] {
        let mut x = Ix::with_key(f_key);
        let f = x.f_ch.clone();
        let pair_default = Node::structure(
            OBJECT_DEFAULTS,
            vec![
                Node::enumeration(OBJECT_TYPE, 4),
                Node::structure(
                    ATTRIBUTES,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 3072),
                    ],
                ),
            ],
        );
        payload(&x.one(
            &f,
            "alice",
            V21,
            None,
            SET_DEFAULTS,
            vec![Node::structure(DEFAULTS_INFORMATION, vec![pair_default])],
        ));
        let r = x.re_provision_generated(V21);
        all_ok(&r);
        let certificate = certificate_link(V21, &r[2]);
        let r = x.one(
            &f,
            "alice",
            V21,
            None,
            GET,
            vec![identifier(V21, &certificate)],
        );
        let public = certificate_value(&r).public_key().unwrap();
        assert_eq!(public.id(), expected);
        if expected == Id::RSA {
            assert_eq!(public.bits(), 2048);
        }
    }
}

#[test]
fn the_message_scoped_key_is_gone_for_everyone_after_the_message() {
    let mut x = Ix::new();
    let (f, g, b) = (x.f_ch.clone(), x.g_ch.clone(), x.b_ch.clone());
    let delegated = x.delegate(&g, vec![right(&[GET], vec![], None)]);
    let r = x.re_provision_generated(V21);
    all_ok(&r);
    let key = uid(&r[0]);
    for (ch, owner, auth) in [
        (&f, "alice", None),
        (&g, "alice", None),
        (&b, "bob", by_ticket(&delegated)),
    ] {
        let r = x.one(ch, owner, V21, auth, GET, vec![identifier(V21, &key)]);
        assert_eq!(reason(&r), OBJECT_NOT_FOUND, "{owner}");
    }
}
