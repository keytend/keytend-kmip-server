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

//! Certify and Re-certify with a caller-designated CA. Issued certificates are
//! verified independently with OpenSSL path validation, not server metadata.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::{Store, now},
    tags::*,
    ttlv::Node,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{
        X509, X509NameBuilder, X509Req, X509ReqBuilder, X509StoreContext,
        extension::{BasicConstraints, KeyUsage, SubjectAlternativeName},
        store::X509StoreBuilder,
    },
};

struct Fixture {
    _dir: tempfile::TempDir,
    e: Engine,
}
impl Fixture {
    fn new() -> Self {
        let d = tempfile::tempdir().unwrap();
        let master = d.path().join("master");
        std::fs::write(&master, [7; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&d.path().join("store"), &master).unwrap();
        Self {
            _dir: d,
            e: Engine::new(store, true),
        }
    }
}
fn message(v: Version, op: u32, p: Vec<Node>) -> Node {
    let mut h = vec![v.node()];
    if v.0 < 3 {
        h.push(Node::int(BATCH_COUNT, 1));
    }
    Node::structure(
        REQUEST_MESSAGE,
        vec![
            Node::structure(REQUEST_HEADER, h),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, op),
                    Node::structure(REQUEST_PAYLOAD, p),
                ],
            ),
        ],
    )
}
fn call(f: &mut Fixture, v: Version, owner: &str, op: u32, p: Vec<Node>) -> Node {
    f.e.process(owner, &message(v, op, p)).unwrap()
}
fn item(n: &Node) -> &Node {
    n.get(BATCH_ITEM).unwrap()
}
fn ok(n: &Node) -> &Node {
    let i = item(n);
    assert_eq!(
        i.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{}",
        serde_json::to_string(n).unwrap()
    );
    i.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(n: &Node) -> u32 {
    let i = item(n);
    assert_eq!(i.required(RESULT_STATUS).unwrap().number().unwrap(), 1);
    i.required(RESULT_REASON).unwrap().number().unwrap()
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn id_of(n: &Node) -> String {
    ok(n)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn link(v: Version, kind: u32, id: &str) -> Node {
    if v.0 >= 3 {
        let tag = match kind {
            0x101 => CERTIFICATE_LINK,
            0x102 => PUBLIC_KEY_LINK,
            0x103 => PRIVATE_KEY_LINK,
            0x106 => REPLACEMENT_OBJECT_LINK,
            _ => panic!("test link"),
        };
        Node::reference(tag, id)
    } else {
        Node::structure(
            LINK,
            vec![
                Node::enumeration(LINK_TYPE, kind),
                Node::text(LINKED_OBJECT_IDENTIFIER, id),
            ],
        )
    }
}
fn name(v: Version, value: &str) -> Node {
    if v.0 >= 3 {
        Node::text(NAME, value)
    } else {
        Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, value),
                Node::enumeration(NAME_TYPE, 1),
            ],
        )
    }
}
fn container(v: Version, attrs: Vec<Node>) -> Node {
    if v.0 == 1 {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            attrs
                .into_iter()
                .map(|mut a| {
                    let name = tag_name(a.tag).unwrap();
                    a.tag = ATTRIBUTE_VALUE;
                    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), a])
                })
                .collect(),
        )
    } else {
        Node::structure(ATTRIBUTES, attrs)
    }
}
fn request_tag(v: Version) -> u32 {
    if v.0 == 1 {
        CERTIFICATE_REQUEST
    } else {
        CERTIFICATE_REQUEST_VALUE
    }
}
fn rsa() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}
fn register_key(
    f: &mut Fixture,
    v: Version,
    owner: &str,
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
    id_of(&call(
        f,
        v,
        owner,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            container(v, extra),
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
fn register_certificate(
    f: &mut Fixture,
    v: Version,
    owner: &str,
    cert: &X509,
    mut extra: Vec<Node>,
) -> String {
    let der = cert.to_der().unwrap();
    extra.extend([
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x1000 | 2),
    ]);
    if v >= Version(1, 1) {
        extra.push(Node::int(CERTIFICATE_LENGTH, der.len() as i32));
    }
    id_of(&call(
        f,
        v,
        owner,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 1),
            container(v, extra),
            Node::structure(
                CERTIFICATE,
                vec![
                    Node::enumeration(CERTIFICATE_TYPE, 1),
                    Node::bytes(CERTIFICATE_VALUE, der),
                ],
            ),
        ],
    ))
}
fn activate(f: &mut Fixture, v: Version, owner: &str, id: &str) {
    ok(&call(f, v, owner, 18, vec![uid(v, id)]));
}
fn ca_certificate(key: &PKey<Private>, ca: bool) -> X509 {
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
    let mut bc = BasicConstraints::new();
    bc.critical();
    if ca {
        bc.ca();
    }
    b.append_extension(bc.build().unwrap()).unwrap();
    let mut ku = KeyUsage::new();
    ku.critical().key_cert_sign().crl_sign().digital_signature();
    b.append_extension(ku.build().unwrap()).unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build()
}
struct Ca {
    certificate: X509,
    id: String,
}
/// Register a caller-owned CA: certificate -> Public Key Link -> public key ->
/// Private Key Link -> private key, all Active.
fn ca(f: &mut Fixture, v: Version, owner: &str, usage: i32, is_ca: bool) -> Ca {
    let key = rsa();
    let certificate = ca_certificate(&key, is_ca);
    let private = register_key(f, v, owner, &key, true, usage, vec![]);
    let public = register_key(f, v, owner, &key, false, 2, vec![link(v, 0x103, &private)]);
    let id = register_certificate(f, v, owner, &certificate, vec![link(v, 0x102, &public)]);
    activate(f, v, owner, &private);
    activate(f, v, owner, &id);
    Ca { certificate, id }
}
fn csr(key: &PKey<Private>, cn: &str) -> X509Req {
    let mut b = X509ReqBuilder::new().unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    b.set_subject_name(&name.build()).unwrap();
    b.set_pubkey(key).unwrap();
    let mut extensions = Stack::new().unwrap();
    extensions
        .push(
            SubjectAlternativeName::new()
                .dns("client.example")
                .ip("10.0.0.1")
                .build(&b.x509v3_context(None))
                .unwrap(),
        )
        .unwrap();
    b.add_extensions(&extensions).unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build()
}
fn get_certificate(f: &mut Fixture, v: Version, owner: &str, id: &str) -> X509 {
    let r = call(f, v, owner, 10, vec![uid(v, id)]);
    let value = ok(&r)
        .required(CERTIFICATE)
        .unwrap()
        .required(CERTIFICATE_VALUE)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec();
    X509::from_der(&value).unwrap()
}
/// Independent check: OpenSSL chain validation against the test CA only.
fn verify_chain(ca: &X509, leaf: &X509) {
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(ca.clone()).unwrap();
    let store = store.build();
    let mut context = X509StoreContext::new().unwrap();
    let chain = Stack::new().unwrap();
    assert!(
        context
            .init(&store, leaf, &chain, |c| c.verify_cert())
            .unwrap(),
        "issued certificate does not chain to the designated CA"
    );
    assert_eq!(
        leaf.issuer_name().to_der().unwrap(),
        ca.subject_name().to_der().unwrap()
    );
    let text = String::from_utf8(leaf.to_text().unwrap()).unwrap();
    assert!(text.contains("CA:FALSE"), "{text}");
    assert!(text.contains("DNS:client.example"), "{text}");
    assert!(text.contains("IP Address:10.0.0.1"), "{text}");
}
/// Link targets of one type from Get Attributes, for any version encoding.
fn links(f: &mut Fixture, v: Version, owner: &str, id: &str, kind: u32) -> Vec<String> {
    let r = call(f, v, owner, 11, vec![uid(v, id)]);
    let p = ok(&r);
    let attrs: Vec<Node> = if v.0 == 1 {
        p.all(ATTRIBUTE)
            .filter(|a| a.required(ATTRIBUTE_NAME).unwrap().string().unwrap() == "Link")
            .map(|a| {
                let mut value = a.required(ATTRIBUTE_VALUE).unwrap().clone();
                value.tag = LINK;
                value
            })
            .collect()
    } else {
        p.required(ATTRIBUTES).unwrap().children().unwrap().to_vec()
    };
    let typed = match kind {
        0x101 => CERTIFICATE_LINK,
        0x102 => PUBLIC_KEY_LINK,
        0x106 => REPLACEMENT_OBJECT_LINK,
        0x107 => REPLACED_OBJECT_LINK,
        _ => 0,
    };
    attrs
        .iter()
        .filter_map(|a| {
            if a.tag == LINK && a.required(LINK_TYPE).unwrap().number().unwrap() == kind {
                Some(
                    a.required(LINKED_OBJECT_IDENTIFIER)
                        .unwrap()
                        .identifier_text()
                        .unwrap()
                        .to_owned(),
                )
            } else if a.tag == typed {
                Some(a.identifier_text().unwrap().to_owned())
            } else {
                None
            }
        })
        .collect()
}
fn has_name(f: &mut Fixture, v: Version, owner: &str, id: &str) -> bool {
    let r = call(f, v, owner, 11, vec![uid(v, id)]);
    let p = ok(&r);
    if v.0 == 1 {
        p.all(ATTRIBUTE)
            .any(|a| a.required(ATTRIBUTE_NAME).unwrap().string().unwrap() == "Name")
    } else {
        p.required(ATTRIBUTES)
            .unwrap()
            .children()
            .unwrap()
            .iter()
            .any(|a| a.tag == NAME)
    }
}
fn certify_payload(
    v: Version,
    public: Option<&str>,
    kind: u32,
    request: Vec<u8>,
    attrs: Vec<Node>,
) -> Vec<Node> {
    let mut p = vec![];
    if let Some(public) = public {
        p.push(uid(v, public));
    }
    p.push(Node::enumeration(CERTIFICATE_REQUEST_TYPE, kind));
    p.push(Node::bytes(request_tag(v), request));
    p.push(container(v, attrs));
    p
}
const VERSIONS: [Version; 8] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
    Version(3, 0),
];

// REQ:5d042a17930b1df6 2.x Quantum Safe profile: Certify and Re-certify work in every edition (other listed operations: tests/profile_conditions.rs)
// REQ:3c47ce45e3b043e2 1.0/1.1 the public key and the new certificate link to each other
// REQ:bd89aa6f91575cb6 the public key gets a Certificate link to the new certificate
// REQ:2918c4246b9ff9da the new certificate gets a Public Key link to the public key
// REQ:38bc3666c27386d7 the renewed certificate gets a Replacement link to the new one
// REQ:3fb35f365ad21eb3 the new certificate gets a Replaced link to the renewed one
// REQ:2d61c77ad8a8f8a7 the public key's Certificate link moves to the new certificate
#[test]
fn certify_and_recertify_issue_verifiable_linked_certificates() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let authority = ca(&mut f, v, "alice", 0x1000 | 1, true);
        let subject = rsa();
        let public = register_key(&mut f, v, "alice", &subject, false, 3, vec![]);
        // PKCS#10 DER in odd minors, PEM otherwise: both request types are supported.
        let request = csr(&subject, &format!("client {}.{}", v.0, v.1));
        let (kind, bytes) = if v.1 % 2 == 1 {
            (2, request.to_der().unwrap())
        } else {
            (3, request.to_pem().unwrap())
        };
        let r = call(
            &mut f,
            v,
            "alice",
            6,
            certify_payload(
                v,
                Some(&public),
                kind,
                bytes,
                vec![
                    link(v, 0x101, &authority.id),
                    name(v, &format!("leaf-{}.{}", v.0, v.1)),
                ],
            ),
        );
        let first = id_of(&r);
        let issued = get_certificate(&mut f, v, "alice", &first);
        verify_chain(&authority.certificate, &issued);
        assert!(issued.public_key().unwrap().public_eq(&subject));
        assert_eq!(
            issued
                .subject_name()
                .entries_by_nid(Nid::COMMONNAME)
                .next()
                .unwrap()
                .data()
                .to_string()
                .unwrap(),
            format!("client {}.{}", v.0, v.1)
        );
        // 1.0 4.6 / 2.1 6.1.6: the public key and certificate point at each other.
        assert_eq!(
            links(&mut f, v, "alice", &public, 0x101),
            vec![first.clone()]
        );
        assert_eq!(
            links(&mut f, v, "alice", &first, 0x102),
            vec![public.clone()]
        );
        assert_eq!(
            links(&mut f, v, "alice", &first, 0x101),
            vec![authority.id.clone()]
        );

        // Re-certify the same key pair: new serial, Replaced/Replacement links,
        // the public key's Certificate Link moves, and the Name moves.
        let renewal = csr(&subject, "renewed");
        let mut p = vec![
            uid(v, &first),
            Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
            Node::bytes(request_tag(v), renewal.to_der().unwrap()),
        ];
        if v >= Version(2, 0) {
            p.push(Node::interval(OFFSET, 3600));
        }
        let second = id_of(&call(&mut f, v, "alice", 7, p));
        let renewed = get_certificate(&mut f, v, "alice", &second);
        verify_chain(&authority.certificate, &renewed);
        assert!(renewed.public_key().unwrap().public_eq(&subject));
        assert_ne!(
            renewed.serial_number().to_bn().unwrap(),
            issued.serial_number().to_bn().unwrap()
        );
        assert_eq!(
            links(&mut f, v, "alice", &first, 0x106),
            vec![second.clone()]
        );
        assert_eq!(
            links(&mut f, v, "alice", &second, 0x107),
            vec![first.clone()]
        );
        assert_eq!(
            links(&mut f, v, "alice", &public, 0x101),
            vec![second.clone()]
        );
        assert!(!has_name(&mut f, v, "alice", &first));
        assert!(has_name(&mut f, v, "alice", &second));
        // Re-certify SHOULD be performed once; a second renewal is refused.
        let again = call(
            &mut f,
            v,
            "alice",
            7,
            vec![
                uid(v, &first),
                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                Node::bytes(request_tag(v), renewal.to_der().unwrap()),
            ],
        );
        assert_eq!(reason(&again), 12);
    }
}

#[test]
fn recertify_without_request_renews_subject_in_2x_and_offset_conflicts_fail() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let authority = ca(&mut f, v, "alice", 0x1000, true);
        let subject = rsa();
        let public = register_key(&mut f, v, "alice", &subject, false, 1, vec![]);
        let first = id_of(&call(
            &mut f,
            v,
            "alice",
            6,
            certify_payload(
                v,
                Some(&public),
                2,
                csr(&subject, "kept").to_der().unwrap(),
                vec![link(v, 0x101, &authority.id)],
            ),
        ));
        // Offset with an explicit Activation Date is Invalid Message (1.0 table 233).
        let conflict = call(
            &mut f,
            v,
            "alice",
            7,
            vec![
                uid(v, &first),
                Node::interval(OFFSET, 10),
                container(v, vec![Node::date(ACTIVATION_DATE, now() + 100)]),
            ],
        );
        assert_eq!(reason(&conflict), 4);
        let second = id_of(&call(&mut f, v, "alice", 7, vec![uid(v, &first)]));
        let renewed = get_certificate(&mut f, v, "alice", &second);
        verify_chain(&authority.certificate, &renewed);
        assert_eq!(
            renewed.subject_name().to_der().unwrap(),
            get_certificate(&mut f, v, "alice", &first)
                .subject_name()
                .to_der()
                .unwrap()
        );
    }
}

#[test]
fn certify_rejects_ambiguous_foreign_or_invalid_requests() {
    for v in [Version(1, 0), Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let authority = ca(&mut f, v, "alice", 0x1000, true);
        let subject = rsa();
        let public = register_key(&mut f, v, "alice", &subject, false, 1, vec![]);
        let good = csr(&subject, "client").to_der().unwrap();
        let attempt = |f: &mut Fixture,
                       owner: &str,
                       public: &str,
                       kind: u32,
                       request: Vec<u8>,
                       attrs: Vec<Node>| {
            reason(&call(
                f,
                v,
                owner,
                6,
                certify_payload(v, Some(public), kind, request, attrs),
            ))
        };
        let issuer = || vec![link(v, 0x101, &authority.id)];
        // No designated issuer: the server never chooses a CA.
        assert_eq!(
            attempt(&mut f, "alice", &public, 2, good.clone(), vec![]),
            12
        );
        // CRMF is defined by KMIP but not implemented.
        assert_eq!(
            attempt(&mut f, "alice", &public, 1, good.clone(), issuer()),
            8
        );
        // A request whose signature does not verify.
        let mut tampered = good.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            attempt(&mut f, "alice", &public, 2, tampered, issuer()),
            if v.0 >= 2 { 0x2f } else { 7 }
        );
        // DER labelled PEM is not a request of the specified type.
        assert_eq!(
            attempt(&mut f, "alice", &public, 3, good.clone(), issuer()),
            if v.0 >= 2 { 0x2f } else { 7 }
        );
        // A request for a different key than the Public Key being certified.
        let other = csr(&rsa(), "other").to_der().unwrap();
        assert_eq!(attempt(&mut f, "alice", &public, 2, other, issuer()), 7);
        // Another owner can neither certify alice's key nor use alice's CA.
        assert_eq!(
            attempt(&mut f, "bob", &public, 2, good.clone(), issuer()),
            1
        );
        let bob_key = rsa();
        let bob_public = register_key(&mut f, v, "bob", &bob_key, false, 1, vec![]);
        assert_eq!(
            attempt(
                &mut f,
                "bob",
                &bob_public,
                2,
                csr(&bob_key, "bob").to_der().unwrap(),
                issuer()
            ),
            1
        );
        // A certificate is not a public key.
        assert_eq!(
            attempt(&mut f, "alice", &authority.id, 2, good.clone(), issuer()),
            if v.0 >= 2 { 0x30 } else { 12 }
        );
        // Only end-entity certificates are issued.
        assert_eq!(
            attempt(
                &mut f,
                "alice",
                &public,
                2,
                good.clone(),
                vec![
                    link(v, 0x101, &authority.id),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x1000)
                ]
            ),
            12
        );
        // The issuing key must permit Certificate Sign, and the issuer must be a CA.
        let unusable = ca(&mut f, v, "alice", 1, true);
        assert_ne!(
            item(&call(
                &mut f,
                v,
                "alice",
                6,
                certify_payload(
                    v,
                    Some(&public),
                    2,
                    good.clone(),
                    vec![link(v, 0x101, &unusable.id)]
                )
            ))
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
            0
        );
        let leaf_issuer = ca(&mut f, v, "alice", 0x1000, false);
        assert_eq!(
            attempt(
                &mut f,
                "alice",
                &public,
                2,
                good.clone(),
                vec![link(v, 0x101, &leaf_issuer.id)]
            ),
            12
        );
        // Re-certify must keep the key pair.
        let first = id_of(&call(
            &mut f,
            v,
            "alice",
            6,
            certify_payload(v, Some(&public), 2, good.clone(), issuer()),
        ));
        let rekeyed = call(
            &mut f,
            v,
            "alice",
            7,
            vec![
                uid(v, &first),
                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                Node::bytes(request_tag(v), csr(&rsa(), "x").to_der().unwrap()),
            ],
        );
        assert_eq!(reason(&rekeyed), 7);
    }
}

#[test]
fn query_lists_certify_and_rejects_client_sent_server_operations() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let r = call(
            &mut f,
            v,
            "alice",
            24,
            vec![Node::enumeration(QUERY_FUNCTION, 1)],
        );
        let ops: Vec<u32> = ok(&r).all(OPERATION).map(|n| n.number().unwrap()).collect();
        assert!(ops.contains(&6) && ops.contains(&7));
        // Notify and Put are only sent by a server; none is configured here.
        assert!(!ops.contains(&27) && !ops.contains(&28));
        for op in [27, 28] {
            assert_eq!(reason(&call(&mut f, v, "alice", op, vec![])), 5);
        }
    }
}

fn date_of(f: &mut Fixture, v: Version, id: &str, tag: u32) -> Option<i64> {
    let r = call(f, v, "alice", 11, vec![uid(v, id)]);
    let p = ok(&r);
    let value = if v.0 == 1 {
        p.all(ATTRIBUTE)
            .find(|a| {
                a.required(ATTRIBUTE_NAME).unwrap().string().unwrap() == tag_name(tag).unwrap()
            })
            .map(|a| a.required(ATTRIBUTE_VALUE).unwrap().clone())
    } else {
        p.required(ATTRIBUTES).unwrap().get(tag).cloned()
    };
    value.map(|n| match n.value {
        keytend_kmip_server::ttlv::Value::DateTime(t) => t,
        _ => panic!("not a date"),
    })
}

// REQ:95ff5039e1c971f6 Certify puts the new certificate in the ID Placeholder
// REQ:d0116e51c77bcd8b Re-certify puts the new certificate in the ID Placeholder
// REQ:9b91602898d4e02a Certify takes exactly one public key
// REQ:8dc1505186d27a2e Re-certify renews exactly one certificate
// REQ:bdeea26c9c7f3587 a Certificate Request needs its Certificate Request Type
// REQ:403eb83d95c3229b 1.0/1.1 Re-certify with Offset shifts the new certificate's dates
// REQ:d74d51e748722d70 1.2-2.1 Re-certify with Offset shifts the new certificate's dates
#[test]
fn certify_and_recertify_placeholders_single_targets_and_offset_dates() {
    for v in &VERSIONS[..7] {
        let v = *v;
        let mut f = Fixture::new();
        let authority = ca(&mut f, v, "alice", 0x1000 | 1, true);
        let subject = rsa();
        let public = register_key(&mut f, v, "alice", &subject, false, 3, vec![]);
        let request = csr(&subject, "client").to_der().unwrap();
        let issuer = || vec![link(v, 0x101, &authority.id)];
        let missing_type = call(
            &mut f,
            v,
            "alice",
            6,
            vec![
                uid(v, &public),
                Node::bytes(request_tag(v), request.clone()),
                container(v, issuer()),
            ],
        );
        assert_eq!(reason(&missing_type), 7);
        let mut two = certify_payload(v, Some(&public), 2, request.clone(), issuer());
        two.insert(0, uid(v, &public));
        assert_ne!(
            item(&call(&mut f, v, "alice", 6, two))
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            0
        );
        let base = now();
        let mut attrs = issuer();
        attrs.push(Node::date(ACTIVATION_DATE, base + 1000));
        attrs.push(Node::date(DEACTIVATION_DATE, base + 9000));
        let batch = |f: &mut Fixture, op: u32, p: Vec<Node>| {
            let mut m = message(v, op, p);
            if let keytend_kmip_server::ttlv::Value::Structure(fields) = &mut m.value {
                if let keytend_kmip_server::ttlv::Value::Structure(h) = &mut fields[0].value {
                    for n in h.iter_mut() {
                        if n.tag == BATCH_COUNT {
                            *n = Node::int(BATCH_COUNT, 2);
                        }
                    }
                }
                if let keytend_kmip_server::ttlv::Value::Structure(first) = &mut fields[1].value {
                    first.insert(1, Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![1]));
                }
                fields.push(Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, 11),
                        Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![2]),
                        Node::structure(REQUEST_PAYLOAD, vec![]),
                    ],
                ));
            }
            let r = f.e.process("alice", &m).unwrap();
            let results: Vec<String> = r
                .all(BATCH_ITEM)
                .map(|i| {
                    assert_eq!(
                        i.required(RESULT_STATUS).unwrap().number().unwrap(),
                        0,
                        "{}.{} {:?}",
                        v.0,
                        v.1,
                        i.get(RESULT_MESSAGE)
                            .map(|m| m.string().unwrap().to_owned())
                    );
                    i.required(RESPONSE_PAYLOAD)
                        .unwrap()
                        .required(UNIQUE_IDENTIFIER)
                        .unwrap()
                        .identifier_text()
                        .unwrap()
                        .to_owned()
                })
                .collect();
            assert_eq!(results.len(), 2);
            assert_eq!(results[0], results[1]);
            results[0].clone()
        };
        let first = batch(
            &mut f,
            6,
            certify_payload(v, Some(&public), 2, request.clone(), attrs),
        );
        let mut renew_two = vec![uid(v, &first), uid(v, &first)];
        renew_two.extend([
            Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
            Node::bytes(request_tag(v), request.clone()),
        ]);
        assert_ne!(
            item(&call(&mut f, v, "alice", 7, renew_two))
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            0
        );
        let second = batch(
            &mut f,
            7,
            vec![
                uid(v, &first),
                Node::interval(OFFSET, 100),
                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                Node::bytes(request_tag(v), request.clone()),
            ],
        );
        assert_ne!(first, second);
        let it1 = date_of(&mut f, v, &first, INITIAL_DATE).unwrap();
        let it2 = date_of(&mut f, v, &second, INITIAL_DATE).unwrap();
        assert!(it2 >= it1);
        let at1 = date_of(&mut f, v, &first, ACTIVATION_DATE).unwrap();
        let at2 = date_of(&mut f, v, &second, ACTIVATION_DATE).unwrap();
        assert_eq!(at2, it2 + 100);
        assert_eq!(
            date_of(&mut f, v, &second, DEACTIVATION_DATE),
            Some(base + 9000 + (at2 - at1))
        );
    }
}

// REQ:786b53abafb92532 2.x Re-certify without a request keeps the existing Certificate Type
// REQ:36606dece09d35fe 1.1-1.4 Re-certify without a request or Certificate Type keeps the existing certificate's type
#[test]
fn recertify_without_request_keeps_the_certificate_type() {
    for v in [
        Version(1, 0),
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
    ] {
        let mut f = Fixture::new();
        let authority = ca(&mut f, v, "alice", 0x1000, true);
        let subject = rsa();
        let public = register_key(&mut f, v, "alice", &subject, false, 1, vec![]);
        let first = id_of(&call(
            &mut f,
            v,
            "alice",
            6,
            certify_payload(
                v,
                Some(&public),
                2,
                csr(&subject, "kept").to_der().unwrap(),
                vec![link(v, 0x101, &authority.id)],
            ),
        ));
        if v == Version(1, 0) {
            // 1.0 section 4.7 has no omitted-request form: the request
            // fields are required (Invalid Field).
            assert_eq!(
                reason(&call(&mut f, v, "alice", 7, vec![uid(v, &first)])),
                7
            );
            continue;
        }
        let second = id_of(&call(&mut f, v, "alice", 7, vec![uid(v, &first)]));
        for id in [&first, &second] {
            let r = call(&mut f, v, "alice", 10, vec![uid(v, id)]);
            assert_eq!(
                ok(&r)
                    .required(CERTIFICATE)
                    .unwrap()
                    .required(CERTIFICATE_TYPE)
                    .unwrap()
                    .number()
                    .unwrap(),
                1
            );
        }
    }
}

/// Certify without a Certificate Request is refused with Feature Not
/// Supported in every edition that permits the form (1.1-1.4 section 4.7,
/// 2.0/2.1 section 6.1.6, draft 3.0 Certify): nothing in the request defines
/// the subject name, and the server does not invent one. 2.0 Table 166 and
/// 2.1 Table 181 list Feature Not Supported for Certify; 1.x defines the
/// reason (1.4 section 9.1.3.2.29) without a Certify-specific row. The
/// clauses on what such a request carries (`e6736c04e72a1194`,
/// `b3b62ae123efd49d`, `855644791ad4b8e9`) are dispositioned as client
/// content rules. Re-certify without a request is implemented (above). 1.0
/// has no omitted-request form.
#[test]
fn certify_without_a_request_is_refused_with_feature_not_supported() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let authority = ca(&mut f, v, "alice", 0x1000, true);
        let subject = rsa();
        let public = register_key(&mut f, v, "alice", &subject, false, 1, vec![]);
        for attrs in [
            vec![link(v, 0x101, &authority.id)],
            vec![
                link(v, 0x101, &authority.id),
                Node::enumeration(CERTIFICATE_TYPE, 1),
            ],
        ] {
            let got = reason(&call(
                &mut f,
                v,
                "alice",
                6,
                vec![uid(v, &public), container(v, attrs)],
            ));
            assert_eq!(got, if v == Version(1, 0) { 7 } else { 8 }, "{v:?}");
        }
        // The key named by its Unique Identifier must still exist and be the
        // caller's: an unknown identifier fails before the form is refused.
        let missing = reason(&call(
            &mut f,
            v,
            "alice",
            6,
            vec![
                uid(v, "no-such-key"),
                container(v, vec![link(v, 0x101, &authority.id)]),
            ],
        ));
        assert_ne!(missing, 0, "{v:?}");
    }
}

fn state_of(f: &mut Fixture, v: Version, id: &str) -> u32 {
    let r = call(f, v, "alice", 11, vec![uid(v, id)]);
    let p = ok(&r);
    if v.0 == 1 {
        p.all(ATTRIBUTE)
            .find(|a| a.required(ATTRIBUTE_NAME).unwrap().string().unwrap() == "State")
            .map(|a| a.required(ATTRIBUTE_VALUE).unwrap().number().unwrap())
            .unwrap()
    } else {
        p.required(ATTRIBUTES)
            .unwrap()
            .required(STATE)
            .unwrap()
            .number()
            .unwrap()
    }
}
fn unix(t: &openssl::asn1::Asn1TimeRef) -> i64 {
    let d = Asn1Time::from_unix(0).unwrap().diff(t).unwrap();
    i64::from(d.days) * 86_400 + i64::from(d.secs)
}

// docs/certificates.md#validity-period
#[test]
fn requested_dates_set_the_validity_of_certify_and_recertify() {
    const YEAR: i64 = 365 * 86_400;
    for v in VERSIONS {
        let mut f = Fixture::new();
        let authority = ca(&mut f, v, "alice", 0x1000 | 1, true);
        let ca_end = unix(authority.certificate.not_after());
        let subject = rsa();
        let request = csr(&subject, "client").to_der().unwrap();
        let certify = |f: &mut Fixture, dates: Vec<Node>| {
            let public = register_key(f, v, "alice", &subject, false, 3, vec![]);
            let mut attrs = vec![link(v, 0x101, &authority.id)];
            attrs.extend(dates);
            call(
                f,
                v,
                "alice",
                6,
                certify_payload(v, Some(&public), 2, request.clone(), attrs),
            )
        };
        // Check the certificate's period, and that only the requested dates
        // are stored, as given.
        let check = |f: &mut Fixture,
                     id: &str,
                     not_before: i64,
                     not_after: i64,
                     stored: (Option<i64>, Option<i64>)| {
            let cert = get_certificate(f, v, "alice", id);
            // Signed by the CA (a later notBefore is not yet valid for a chain check).
            assert!(
                cert.verify(&authority.certificate.public_key().unwrap())
                    .unwrap()
            );
            assert_eq!(
                (unix(cert.not_before()), unix(cert.not_after())),
                (not_before, not_after),
                "{v:?}"
            );
            assert_eq!(
                (
                    date_of(f, v, id, ACTIVATION_DATE),
                    date_of(f, v, id, DEACTIVATION_DATE)
                ),
                stored,
                "{v:?}"
            );
            // No Activation Date: Pre-Active, for the client to activate.
            let state = state_of(f, v, id);
            match stored.0 {
                None => assert_eq!(state, 1, "{v:?}"),
                Some(a) if a > now() => assert_eq!(state, 1, "{v:?}"),
                Some(_) => assert_eq!(state, 2, "{v:?}"),
            }
        };
        let base = now();
        // Both dates.
        let r = certify(
            &mut f,
            vec![
                Node::date(ACTIVATION_DATE, base + 100),
                Node::date(DEACTIVATION_DATE, base + 30 * 86_400),
            ],
        );
        check(
            &mut f,
            &id_of(&r),
            base + 100,
            base + 30 * 86_400,
            (Some(base + 100), Some(base + 30 * 86_400)),
        );
        // Only an Activation Date: a year from it; no Deactivation Date stored.
        let r = certify(&mut f, vec![Node::date(ACTIVATION_DATE, base + 100)]);
        check(
            &mut f,
            &id_of(&r),
            base + 100,
            base + 100 + YEAR,
            (Some(base + 100), None),
        );
        // Only a Deactivation Date: from now, and still Pre-Active.
        let r = certify(&mut f, vec![Node::date(DEACTIVATION_DATE, base + 86_400)]);
        let id = id_of(&r);
        let cert = get_certificate(&mut f, v, "alice", &id);
        let start = unix(cert.not_before());
        assert!((base..=now()).contains(&start));
        check(
            &mut f,
            &id,
            start,
            base + 86_400,
            (None, Some(base + 86_400)),
        );
        // Neither: from now for a year.
        let r = certify(&mut f, vec![]);
        let id = id_of(&r);
        // Without dates the object has none (Pre-Active until activated).
        assert_eq!(date_of(&mut f, v, &id, ACTIVATION_DATE), None);
        assert_eq!(date_of(&mut f, v, &id, DEACTIVATION_DATE), None);
        let cert = get_certificate(&mut f, v, "alice", &id);
        assert_eq!(
            unix(cert.not_after()) - unix(cert.not_before()),
            YEAR,
            "{v:?}"
        );

        // Refused with Invalid Field, never cut short.
        for dates in [
            vec![Node::date(DEACTIVATION_DATE, ca_end + 1)],
            vec![Node::date(ACTIVATION_DATE, ca_end)],
            vec![
                Node::date(ACTIVATION_DATE, base + 1000),
                Node::date(DEACTIVATION_DATE, base + 1000),
            ],
            vec![Node::date(DEACTIVATION_DATE, base - 10)],
        ] {
            assert_eq!(reason(&certify(&mut f, dates)), 7, "{v:?}");
        }
        // Re-certify with explicit dates: the same rules.
        let recertify = |f: &mut Fixture, dates: Vec<Node>| {
            // An existing certificate with both dates (a near-future
            // Activation Date: 1.0 moves a past one to the request time).
            let r = certify(
                f,
                vec![
                    Node::date(ACTIVATION_DATE, base + 5),
                    Node::date(DEACTIVATION_DATE, base + 5 + YEAR),
                ],
            );
            let old = id_of(&r);
            let mut p = vec![
                uid(v, &old),
                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                Node::bytes(request_tag(v), request.clone()),
            ];
            if !dates.is_empty() {
                p.push(container(v, dates));
            }
            call(f, v, "alice", 7, p)
        };
        let r = recertify(
            &mut f,
            vec![
                Node::date(ACTIVATION_DATE, base + 200),
                Node::date(DEACTIVATION_DATE, base + 10 * 86_400),
            ],
        );
        check(
            &mut f,
            &id_of(&r),
            base + 200,
            base + 10 * 86_400,
            (Some(base + 200), Some(base + 10 * 86_400)),
        );
        // Only an Activation Date: the existing certificate's length (a year).
        let r = recertify(&mut f, vec![Node::date(ACTIVATION_DATE, base + 200)]);
        check(
            &mut f,
            &id_of(&r),
            base + 200,
            base + 200 + YEAR,
            (Some(base + 200), None),
        );
        // Only a Deactivation Date: the existing Activation Date is not
        // copied, so the new certificate stays Pre-Active.
        let r = recertify(&mut f, vec![Node::date(DEACTIVATION_DATE, base + 86_400)]);
        let id = id_of(&r);
        let start = unix(get_certificate(&mut f, v, "alice", &id).not_before());
        check(
            &mut f,
            &id,
            start,
            base + 86_400,
            (None, Some(base + 86_400)),
        );
        let r = recertify(&mut f, vec![Node::date(DEACTIVATION_DATE, ca_end + 1)]);
        assert_eq!(reason(&r), 7, "{v:?}");
        let r = recertify(
            &mut f,
            vec![
                Node::date(ACTIVATION_DATE, base + 500),
                Node::date(DEACTIVATION_DATE, base + 400),
            ],
        );
        assert_eq!(reason(&r), 7, "{v:?}");
    }
}
