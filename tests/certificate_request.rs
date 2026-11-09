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

//! The 2.0+ Certificate Request managed object (Object Type 0x0A) and its use
//! by Certify and Re-certify. Issued certificates are checked with OpenSSL.
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
    pkey::{PKey, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{
        X509, X509NameBuilder, X509Req, X509ReqBuilder, X509StoreContext,
        extension::{BasicConstraints, KeyUsage},
        store::X509StoreBuilder,
    },
};

const REQUEST: u32 = 10;
const V1: [Version; 5] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
];
const V2: [Version; 3] = [Version(2, 0), Version(2, 1), Version(3, 0)];

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
    fn batch(&mut self, v: Version, owner: &str, items: Vec<(u32, Vec<Node>)>) -> Node {
        let mut h = vec![v.node()];
        if v.0 < 3 {
            h.push(Node::int(BATCH_COUNT, items.len() as i32));
        }
        let mut fields = vec![Node::structure(REQUEST_HEADER, h)];
        let many = items.len() > 1;
        fields.extend(items.into_iter().enumerate().map(|(i, (op, p))| {
            let mut item = vec![Node::enumeration(OPERATION, op)];
            if many && v.0 < 3 {
                item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8]));
            }
            item.push(Node::structure(REQUEST_PAYLOAD, p));
            Node::structure(BATCH_ITEM, item)
        }));
        self.e
            .process(owner, &Node::structure(REQUEST_MESSAGE, fields))
            .unwrap()
    }
    fn call(&mut self, v: Version, owner: &str, op: u32, p: Vec<Node>) -> Node {
        self.batch(v, owner, vec![(op, p)])
    }
}
fn item(n: &Node, index: usize) -> &Node {
    n.all(BATCH_ITEM)
        .nth(index)
        .unwrap_or_else(|| panic!("{}", serde_json::to_string(n).unwrap()))
}
fn ok_at(n: &Node, index: usize) -> &Node {
    let i = item(n, index);
    assert_eq!(
        i.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{}",
        serde_json::to_string(n).unwrap()
    );
    i.required(RESPONSE_PAYLOAD).unwrap()
}
fn ok(n: &Node) -> &Node {
    ok_at(n, 0)
}
fn reason(n: &Node) -> u32 {
    let i = item(n, 0);
    assert_eq!(
        i.required(RESULT_STATUS).unwrap().number().unwrap(),
        1,
        "{}",
        serde_json::to_string(n).unwrap()
    );
    i.required(RESULT_REASON).unwrap().number().unwrap()
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
/// Re-certify's Certificate Request Unique Identifier field.
fn request_uid(v: Version, id: &str) -> Node {
    let mut n = uid(v, id);
    n.tag = CERTIFICATE_REQUEST_UNIQUE_IDENTIFIER;
    n
}
fn id_at(n: &Node, index: usize) -> String {
    ok_at(n, index)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn id_of(n: &Node) -> String {
    id_at(n, 0)
}
fn link(v: Version, kind: u32, id: &str) -> Node {
    if v.0 >= 3 {
        let tag = match kind {
            0x101 => CERTIFICATE_LINK,
            0x102 => PUBLIC_KEY_LINK,
            0x103 => PRIVATE_KEY_LINK,
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
fn rsa() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}
fn csr(key: &PKey<Private>, cn: &str) -> X509Req {
    let mut b = X509ReqBuilder::new().unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    b.set_subject_name(&name.build()).unwrap();
    b.set_pubkey(key).unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build()
}
fn request_object(kind: u32, value: Vec<u8>) -> Node {
    Node::structure(
        CERTIFICATE_REQUEST,
        vec![
            Node::enumeration(CERTIFICATE_REQUEST_TYPE, kind),
            Node::bytes(CERTIFICATE_REQUEST_VALUE, value),
        ],
    )
}
fn register_payload(v: Version, kind: u32, value: Vec<u8>) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, REQUEST),
        container(v, vec![]),
        request_object(kind, value),
    ]
}
fn register_request(f: &mut Fixture, v: Version, owner: &str, kind: u32, value: Vec<u8>) -> String {
    id_of(&f.call(v, owner, 3, register_payload(v, kind, value)))
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
    id_of(&f.call(
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
fn ca_certificate(key: &PKey<Private>) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Request Test CA").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(9).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(now() - 3600).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(now() + 3 * 365 * 86400).unwrap())
        .unwrap();
    let mut bc = BasicConstraints::new();
    bc.critical().ca();
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
/// A caller-owned, Active CA: certificate -> public key -> private key.
fn ca(f: &mut Fixture, v: Version, owner: &str) -> Ca {
    let key = rsa();
    let certificate = ca_certificate(&key);
    let private = register_key(f, v, owner, &key, true, 0x1000 | 1, vec![]);
    let public = register_key(f, v, owner, &key, false, 2, vec![link(v, 0x103, &private)]);
    let der = certificate.to_der().unwrap();
    let id = id_of(&f.call(
        v,
        owner,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 1),
            container(
                v,
                vec![
                    link(v, 0x102, &public),
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
        ok(&f.call(v, owner, 18, vec![uid(v, target)]));
    }
    Ca { certificate, id }
}
fn get(f: &mut Fixture, v: Version, owner: &str, id: &str, extra: Vec<Node>) -> Node {
    let mut p = vec![uid(v, id)];
    p.extend(extra);
    f.call(v, owner, 10, p)
}
fn certificate(f: &mut Fixture, v: Version, owner: &str, id: &str) -> X509 {
    let r = get(f, v, owner, id, vec![]);
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
fn verify(ca: &X509, leaf: &X509) {
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(ca.clone()).unwrap();
    let store = store.build();
    let mut context = X509StoreContext::new().unwrap();
    let chain = Stack::new().unwrap();
    assert!(
        context
            .init(&store, leaf, &chain, |c| c.verify_cert())
            .unwrap()
    );
}
fn common_name(cert: &X509) -> String {
    cert.subject_name()
        .entries()
        .next()
        .unwrap()
        .data()
        .to_string()
        .unwrap()
}
fn attributes(f: &mut Fixture, v: Version, owner: &str, id: &str) -> Vec<Node> {
    let r = f.call(v, owner, 11, vec![uid(v, id)]);
    ok(&r)
        .required(ATTRIBUTES)
        .unwrap()
        .children()
        .unwrap()
        .to_vec()
}
fn request_links(f: &mut Fixture, v: Version, owner: &str, id: &str) -> Vec<String> {
    attributes(f, v, owner, id)
        .iter()
        .filter(|a| a.tag == CERTIFICATE_REQUEST_LINK)
        .map(|a| a.identifier_text().unwrap().to_owned())
        .collect()
}
fn locate(f: &mut Fixture, v: Version, owner: &str, filter: Node) -> Vec<String> {
    let field = if v.0 >= 2 {
        Node::structure(ATTRIBUTES, vec![filter])
    } else {
        let name = tag_name(filter.tag).unwrap();
        let mut value = filter;
        value.tag = ATTRIBUTE_VALUE;
        Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), value])
    };
    let mut ids: Vec<String> = ok(&f.call(v, owner, 8, vec![field]))
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}
fn query_objects(f: &mut Fixture, v: Version) -> Vec<u32> {
    ok(&f.call(v, "alice", 24, vec![Node::enumeration(QUERY_FUNCTION, 2)]))
        .all(OBJECT_TYPE)
        .map(|n| n.number().unwrap())
        .collect()
}

// REQ:bf4362cc2a68e7d4 2.x Query Objects lists every supported object type, including Certificate Request
#[test]
fn query_objects_lists_certificate_request_only_where_defined() {
    let mut f = Fixture::new();
    for v in V1 {
        assert!(
            !query_objects(&mut f, v).contains(&REQUEST),
            "{}.{}",
            v.0,
            v.1
        );
    }
    for v in V2 {
        assert!(
            query_objects(&mut f, v).contains(&REQUEST),
            "{}.{}",
            v.0,
            v.1
        );
    }
}

// REQ:baa4566dd3929904 draft 3.0 2.2.2: Certificate Request objects carry the minimum attribute set
#[test]
fn certificate_requests_are_registered_returned_located_and_destroyed() {
    for v in V2 {
        let mut f = Fixture::new();
        let key = rsa();
        let request = csr(&key, "requested.example");
        let der = request.to_der().unwrap();
        let pem = request.to_pem().unwrap();
        let der_id = register_request(&mut f, v, "alice", 2, der.clone());
        let pem_id = register_request(&mut f, v, "alice", 3, pem.clone());

        // Get returns the object as registered (2.1 section 2.2, table 3).
        for (id, kind, bytes) in [(&der_id, 2, &der), (&pem_id, 3, &pem)] {
            let r = get(&mut f, v, "alice", id, vec![]);
            let p = ok(&r);
            assert_eq!(p.required(OBJECT_TYPE).unwrap().number().unwrap(), REQUEST);
            let object = p.required(CERTIFICATE_REQUEST).unwrap();
            assert_eq!(
                object
                    .required(CERTIFICATE_REQUEST_TYPE)
                    .unwrap()
                    .number()
                    .unwrap(),
                kind
            );
            assert_eq!(
                object
                    .required(CERTIFICATE_REQUEST_VALUE)
                    .unwrap()
                    .byte_string()
                    .unwrap(),
                &bytes[..]
            );
        }
        // Key Format Type PKCS#10 (0x17), the default for this object
        // (2.1 table 81), yields DER even for a PEM registration. Any other
        // format is Key Format Type Not Supported.
        let r = get(
            &mut f,
            v,
            "alice",
            &pem_id,
            vec![Node::enumeration(KEY_FORMAT_TYPE, 0x17)],
        );
        let object = ok(&r).required(CERTIFICATE_REQUEST).unwrap();
        assert_eq!(
            object
                .required(CERTIFICATE_REQUEST_TYPE)
                .unwrap()
                .number()
                .unwrap(),
            2
        );
        assert_eq!(
            object
                .required(CERTIFICATE_REQUEST_VALUE)
                .unwrap()
                .byte_string()
                .unwrap(),
            &der[..]
        );
        let r = get(
            &mut f,
            v,
            "alice",
            &der_id,
            vec![Node::enumeration(KEY_FORMAT_TYPE, 1)],
        );
        assert_eq!(reason(&r), 0x10);
        let r = get(
            &mut f,
            v,
            "alice",
            &der_id,
            vec![Node::structure(KEY_WRAPPING_SPECIFICATION, vec![])],
        );
        assert_eq!(reason(&r), 8);

        // Attributes: the 3.0 minimum set, Key Format Type PKCS#10, a digest.
        let attrs = attributes(&mut f, v, "alice", &der_id);
        let has = |tag: u32| attrs.iter().any(|a| a.tag == tag);
        for tag in [
            UNIQUE_IDENTIFIER,
            SHORT_UNIQUE_IDENTIFIER,
            OBJECT_TYPE,
            INITIAL_DATE,
            DIGEST,
        ] {
            assert!(has(tag), "{}.{} {tag:x}", v.0, v.1);
        }
        assert_eq!(has(OBJECT_CLASS), v.0 >= 3);
        assert!(!has(CRYPTOGRAPHIC_ALGORITHM));
        let format = attrs.iter().find(|a| a.tag == KEY_FORMAT_TYPE).unwrap();
        assert_eq!(format.number().unwrap(), 0x17);

        // Locate by Object Type finds exactly the requests.
        register_key(&mut f, v, "alice", &key, false, 2, vec![]);
        let mut expected = vec![der_id.clone(), pem_id.clone()];
        expected.sort();
        assert_eq!(
            locate(&mut f, v, "alice", Node::enumeration(OBJECT_TYPE, REQUEST)),
            expected
        );
        // Another owner sees nothing.
        // Object Not Found from 2.0 (docs/messages.md#unknown-identifiers).
        assert_eq!(reason(&get(&mut f, v, "bob", &der_id, vec![])), 0x37);

        // Destroy removes the value.
        ok(&f.call(v, "alice", 20, vec![uid(v, &der_id)]));
        let r = get(&mut f, v, "alice", &der_id, vec![]);
        assert_ne!(
            item(&r, 0)
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            0
        );
    }
}

#[test]
fn register_refuses_invalid_or_unsupported_requests() {
    for v in V2 {
        let mut f = Fixture::new();
        let key = rsa();
        let der = csr(&key, "bad.example").to_der().unwrap();
        // A broken signature: flip the last signature byte.
        let mut tampered = der.clone();
        *tampered.last_mut().unwrap() ^= 1;
        // Non-canonical: trailing data after the DER request.
        let mut trailing = der.clone();
        trailing.push(0);
        // Register lists no Invalid CSR (2.1 table 294): Invalid Field.
        for (kind, bytes, expected) in [
            (2, tampered, 7),
            (2, trailing, 7),
            (2, b"not a request".to_vec(), 7),
            (3, der.clone(), 7),
            (2, vec![], 7),
            // PGP (4) is Reserved from 2.0; CRMF (1) is not implemented.
            (4, der.clone(), 7),
            (1, der.clone(), 8),
        ] {
            let r = f.call(v, "alice", 3, register_payload(v, kind, bytes));
            assert_eq!(reason(&r), expected, "{}.{} type {kind}", v.0, v.1);
        }
        // Unknown structure members and a mismatched object structure.
        let mut fields = register_payload(v, 2, der.clone());
        fields[2] = Node::structure(
            CERTIFICATE_REQUEST,
            vec![
                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                Node::bytes(CERTIFICATE_REQUEST_VALUE, der.clone()),
                Node::structure(KEY_BLOCK, vec![]),
            ],
        );
        assert_ne!(
            item(&f.call(v, "alice", 3, fields), 0)
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            0
        );
        let r = f.call(
            v,
            "alice",
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 1),
                container(v, vec![]),
                request_object(2, der.clone()),
            ],
        );
        assert_eq!(reason(&r), 7);
        // Create cannot make a Certificate Request.
        let r = f.call(
            v,
            "alice",
            1,
            vec![
                Node::enumeration(OBJECT_TYPE, REQUEST),
                container(v, vec![]),
            ],
        );
        assert_eq!(reason(&r), 8);
    }
}

#[test]
fn one_x_has_no_certificate_request_objects() {
    let mut f = Fixture::new();
    let key = rsa();
    let der = csr(&key, "legacy.example").to_der().unwrap();
    let id = register_request(&mut f, Version(2, 1), "alice", 2, der.clone());
    for v in V1 {
        // The 1.x Object Type enumeration has no Certificate Request.
        let r = f.call(v, "alice", 3, register_payload(v, 2, der.clone()));
        assert_eq!(reason(&r), 8, "{}.{}", v.0, v.1);
        // Objects registered through 2.x are invisible, like 1.x Templates in 2.x.
        assert_eq!(
            reason(&get(&mut f, v, "alice", &id, vec![])),
            1,
            "{}.{}",
            v.0,
            v.1
        );
        assert_eq!(reason(&f.call(v, "alice", 11, vec![uid(v, &id)])), 1);
        assert!(locate(&mut f, v, "alice", Node::enumeration(OBJECT_TYPE, REQUEST)).is_empty());
    }
}

// REQ:2650edac547c749a draft 3.0 Certify: the Unique Identifier may name the Certificate Request to certify
// REQ:99e818bcf338a490 draft 3.0 4.35.2: a certificate from a Certificate Request has a Certificate Request Link
#[test]
fn certify_issues_a_certificate_for_a_certificate_request_object() {
    for v in V2 {
        let mut f = Fixture::new();
        let authority = ca(&mut f, v, "alice");
        let subject = rsa();
        let request = csr(&subject, &format!("by-object {}.{}", v.0, v.1));
        let request_id = register_request(&mut f, v, "alice", 3, request.to_pem().unwrap());
        let issuer = Node::structure(ATTRIBUTES, vec![link(v, 0x101, &authority.id)]);
        let r = f.call(v, "alice", 6, vec![uid(v, &request_id), issuer.clone()]);
        let id = id_of(&r);
        let issued = certificate(&mut f, v, "alice", &id);
        verify(&authority.certificate, &issued);
        assert_eq!(common_name(&issued), format!("by-object {}.{}", v.0, v.1));
        assert!(issued.public_key().unwrap().public_eq(&subject));
        // Draft 3.0 links the certificate to its request; 2.x defines no
        // such attribute or Link Type (2.1 table 465) and shows none.
        let links = request_links(&mut f, v, "alice", &id);
        if v.0 >= 3 {
            assert_eq!(links, vec![request_id.clone()]);
            // The link is searchable in the draft.
            assert_eq!(
                locate(
                    &mut f,
                    v,
                    "alice",
                    Node::reference(CERTIFICATE_REQUEST_LINK, &request_id)
                ),
                vec![id.clone()]
            );
        } else {
            assert!(links.is_empty());
        }

        // The ID Placeholder can carry the request from Register in the same batch.
        let request = csr(&subject, "placeholder.example").to_der().unwrap();
        let r = f.batch(
            v,
            "alice",
            vec![
                (3, register_payload(v, 2, request)),
                (6, vec![issuer.clone()]),
            ],
        );
        let id = id_at(&r, 1);
        assert_eq!(
            common_name(&certificate(&mut f, v, "alice", &id)),
            "placeholder.example"
        );

        // A request given both by identifier and inline is ambiguous.
        let inline = csr(&subject, "inline.example").to_der().unwrap();
        let r = f.call(
            v,
            "alice",
            6,
            vec![
                uid(v, &request_id),
                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                Node::bytes(CERTIFICATE_REQUEST_VALUE, inline),
                issuer.clone(),
            ],
        );
        assert_eq!(reason(&r), 7);
        // Another owner cannot use the request.
        let foreign = ca(&mut f, v, "bob");
        let r = f.call(
            v,
            "bob",
            6,
            vec![
                uid(v, &request_id),
                Node::structure(ATTRIBUTES, vec![link(v, 0x101, &foreign.id)]),
            ],
        );
        assert_eq!(reason(&r), 1);
        // A Deactivated request is no longer certified.
        ok(&f.call(v, "alice", 18, vec![uid(v, &request_id)]));
        ok(&f.call(
            v,
            "alice",
            19,
            vec![
                uid(v, &request_id),
                Node::structure(
                    REVOCATION_REASON,
                    vec![Node::enumeration(REVOCATION_REASON_CODE, 5)],
                ),
            ],
        ));
        let r = f.call(v, "alice", 6, vec![uid(v, &request_id), issuer]);
        assert_eq!(reason(&r), 12);
    }
}

#[test]
fn recertify_uses_a_certificate_request_unique_identifier() {
    for v in V2 {
        let mut f = Fixture::new();
        let authority = ca(&mut f, v, "alice");
        let subject = rsa();
        let public = register_key(&mut f, v, "alice", &subject, false, 3, vec![]);
        let issuer = Node::structure(ATTRIBUTES, vec![link(v, 0x101, &authority.id)]);
        let first = csr(&subject, "first.example").to_der().unwrap();
        let old = id_of(&f.call(
            v,
            "alice",
            6,
            vec![
                uid(v, &public),
                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                Node::bytes(CERTIFICATE_REQUEST_VALUE, first),
                issuer.clone(),
            ],
        ));
        ok(&f.call(v, "alice", 18, vec![uid(v, &old)]));
        let renewal = csr(&subject, "renewed.example").to_der().unwrap();
        let request_id = register_request(&mut f, v, "alice", 2, renewal.clone());
        let r = f.call(
            v,
            "alice",
            7,
            vec![uid(v, &old), request_uid(v, &request_id)],
        );
        let new = id_of(&r);
        let renewed = certificate(&mut f, v, "alice", &new);
        verify(&authority.certificate, &renewed);
        assert_eq!(common_name(&renewed), "renewed.example");
        let links = request_links(&mut f, v, "alice", &new);
        assert_eq!(
            links,
            if v.0 >= 3 {
                vec![request_id.clone()]
            } else {
                vec![]
            }
        );

        // The identifier must name a Certificate Request for the same key pair.
        let r = f.call(v, "alice", 7, vec![uid(v, &new), request_uid(v, &public)]);
        assert_eq!(reason(&r), 0x30);
        let other = rsa();
        let other_id = register_request(&mut f, v, "alice", 2, csr(&other, "x").to_der().unwrap());
        let r = f.call(v, "alice", 7, vec![uid(v, &new), request_uid(v, &other_id)]);
        assert_eq!(reason(&r), 7);
        // Both an identifier and an inline request is ambiguous.
        let r = f.call(
            v,
            "alice",
            7,
            vec![
                uid(v, &new),
                request_uid(v, &request_id),
                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                Node::bytes(CERTIFICATE_REQUEST_VALUE, renewal),
            ],
        );
        assert_eq!(reason(&r), 7);
    }
}

#[test]
fn certificate_request_link_is_a_draft_only_client_attribute() {
    let v = Version(3, 0);
    let mut f = Fixture::new();
    let key = rsa();
    let request_id = register_request(&mut f, v, "alice", 2, csr(&key, "k").to_der().unwrap());
    let public = register_key(&mut f, v, "alice", &key, false, 2, vec![]);
    // Draft 3.0 table 132: client-set, multi-valued and modifiable.
    for _ in 0..2 {
        ok(&f.call(
            v,
            "alice",
            13,
            vec![
                uid(v, &public),
                Node::structure(
                    NEW_ATTRIBUTE,
                    vec![Node::reference(CERTIFICATE_REQUEST_LINK, &request_id)],
                ),
            ],
        ));
    }
    assert_eq!(request_links(&mut f, v, "alice", &public).len(), 2);
    let r = f.call(
        v,
        "alice",
        13,
        vec![
            uid(v, &public),
            Node::structure(
                NEW_ATTRIBUTE,
                vec![Node::text(CERTIFICATE_REQUEST_LINK, &request_id)],
            ),
        ],
    );
    assert_eq!(reason(&r), 7);
    // 2.1 neither accepts nor shows the draft attribute.
    let v21 = Version(2, 1);
    let r = f.call(
        v21,
        "alice",
        13,
        vec![
            uid(v21, &public),
            Node::structure(
                NEW_ATTRIBUTE,
                vec![Node::text(CERTIFICATE_REQUEST_LINK, &request_id)],
            ),
        ],
    );
    assert_ne!(
        item(&r, 0)
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
        0
    );
    let r = f.call(
        v21,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 3),
            Node::structure(
                ATTRIBUTES,
                vec![Node::text(CERTIFICATE_REQUEST_LINK, &request_id)],
            ),
            Node::structure(PUBLIC_KEY, vec![]),
        ],
    );
    assert_eq!(reason(&r), 8);
    assert!(request_links(&mut f, v21, "alice", &public).is_empty());
}

#[test]
fn certificate_requests_are_not_split() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let key = rsa();
    let request_id = register_request(&mut f, v, "alice", 2, csr(&key, "s").to_der().unwrap());
    let r = f.call(
        v,
        "alice",
        40,
        vec![
            Node::enumeration(OBJECT_TYPE, 5),
            Node::int(SPLIT_KEY_PARTS, 2),
            Node::int(SPLIT_KEY_THRESHOLD, 2),
            Node::enumeration(SPLIT_KEY_METHOD, 1),
            container(v, vec![]),
            uid(v, &request_id),
        ],
    );
    assert_eq!(reason(&r), 8, "{}", serde_json::to_string(&r).unwrap());
}
