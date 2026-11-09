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
    certificates::CertificateValidation,
    protocol::{Engine, Version},
    store::{Store, now},
    tags::*,
    ttlv::Node,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        X509, X509NameBuilder,
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    },
};
fn issue(
    name: &str,
    serial: u32,
    issuer: Option<(&X509, &PKey<Private>)>,
    ca: bool,
    start: i64,
    end: i64,
) -> (X509, PKey<Private>) {
    let key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    let mut n = X509NameBuilder::new().unwrap();
    n.append_entry_by_text("CN", name).unwrap();
    let n = n.build();
    b.set_subject_name(&n).unwrap();
    b.set_issuer_name(issuer.map(|(c, _)| c.subject_name()).unwrap_or(&n))
        .unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(start).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(end).unwrap()).unwrap();
    let mut bc = BasicConstraints::new();
    bc.critical();
    if ca {
        bc.ca();
    }
    b.append_extension(bc.build().unwrap()).unwrap();
    let mut ku = KeyUsage::new();
    ku.critical();
    if ca {
        ku.key_cert_sign().crl_sign();
    } else {
        ku.digital_signature();
    }
    b.append_extension(ku.build().unwrap()).unwrap();
    let ski = SubjectKeyIdentifier::new()
        .build(&b.x509v3_context(issuer.map(|(c, _)| c.as_ref()), None))
        .unwrap();
    b.append_extension(ski).unwrap();
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&b.x509v3_context(issuer.map(|(c, _)| c.as_ref()), None))
        .unwrap();
    b.append_extension(aki).unwrap();
    b.sign(
        issuer.map(|(_, k)| k).unwrap_or(&key),
        MessageDigest::sha256(),
    )
    .unwrap();
    (b.build(), key)
}
struct Pki {
    root: X509,
    intermediate: X509,
    leaf: X509,
    other: X509,
    at: i64,
}
impl Pki {
    fn new() -> Self {
        let at = now();
        let (root, key) = issue("root", 1, None, true, at - 10000, at + 10000);
        let (intermediate, ikey) = issue(
            "intermediate",
            2,
            Some((&root, &key)),
            true,
            at - 5000,
            at + 5000,
        );
        let (leaf, _) = issue(
            "leaf",
            3,
            Some((&intermediate, &ikey)),
            false,
            at - 1000,
            at + 1000,
        );
        let (other, _) = issue("untrusted-root", 4, None, true, at - 10000, at + 10000);
        Self {
            root,
            intermediate,
            leaf,
            other,
            at,
        }
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    e: Engine,
}
impl Fixture {
    fn new(root: Option<&X509>) -> Self {
        let d = tempfile::tempdir().unwrap();
        let master = d.path().join("master");
        std::fs::write(&master, [9; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&d.path().join("store"), &master).unwrap();
        let policy = root
            .map(|r| CertificateValidation::from_pem(&r.to_pem().unwrap()).unwrap())
            .unwrap_or_default();
        Self {
            _dir: d,
            e: Engine::new(store, true).with_certificate_validation(policy),
        }
    }
}
fn cert(c: &X509) -> Node {
    structure(
        CERTIFICATE,
        vec![
            Node::enumeration(CERTIFICATE_TYPE, 1),
            Node::bytes(CERTIFICATE_VALUE, c.to_der().unwrap()),
        ],
    )
}
fn structure(t: u32, c: Vec<Node>) -> Node {
    Node::structure(t, c)
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn message(v: Version, items: Vec<(u32, Vec<Node>)>, extra: Vec<Node>) -> Node {
    let mut h = vec![v.node()];
    if v.0 < 3 {
        h.push(Node::int(BATCH_COUNT, items.len() as i32));
    }
    h.extend(extra);
    let mut f = vec![structure(REQUEST_HEADER, h)];
    for (i, (op, p)) in items.into_iter().enumerate() {
        let mut b = vec![
            Node::enumeration(OPERATION, op),
            structure(REQUEST_PAYLOAD, p),
        ];
        if v.0 < 3 {
            b.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8]));
        }
        f.push(structure(BATCH_ITEM, b));
    }
    structure(REQUEST_MESSAGE, f)
}
fn call(f: &mut Fixture, v: Version, op: u32, p: Vec<Node>) -> Node {
    f.e.process("owner", &message(v, vec![(op, p)], vec![]))
        .unwrap()
}
fn body(n: &Node) -> &Node {
    let i = n.get(BATCH_ITEM).unwrap();
    assert_eq!(
        i.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{}",
        serde_json::to_string(n).unwrap()
    );
    i.required(RESPONSE_PAYLOAD).unwrap()
}
fn validity(n: &Node) -> u32 {
    body(n)
        .required(VALIDITY_INDICATOR)
        .unwrap()
        .number()
        .unwrap()
}
/// Item Not Found in 1.x; Object Not Found in the 2.x and draft 3.0 error
/// tables (2.1 Tables 339 Signature Verify and 342 Validate).
fn not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x37 } else { 1 }
}
fn reason(n: &Node) -> u32 {
    n.get(BATCH_ITEM)
        .unwrap()
        .required(RESULT_REASON)
        .unwrap()
        .number()
        .unwrap()
}
fn register(f: &mut Fixture, v: Version, c: &X509) -> String {
    body(&call(
        f,
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 1),
            cert(c),
            attributes(
                v,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
                ]
                .into_iter()
                .chain(
                    (v >= Version(1, 1))
                        .then(|| Node::int(CERTIFICATE_LENGTH, c.to_der().unwrap().len() as i32)),
                )
                .collect(),
            ),
        ],
    ))
    .required(UNIQUE_IDENTIFIER)
    .unwrap()
    .identifier_text()
    .unwrap()
    .to_owned()
}
fn versions() -> [Version; 8] {
    [
        Version(1, 0),
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ]
}
#[test]
fn validation_identifier_capacity_is_an_item_failure_with_durable_batch_statuses() {
    for v in versions() {
        for continuation in [1, 2, 3] {
            let mut f = Fixture::new(None);
            // At the boundary, identifiers reach object validation. The first
            // missing object is a lookup failure, not a capacity refusal.
            let fields = (0..32).map(|i| uid(v, &format!("missing-{i}"))).collect();
            assert_eq!(reason(&call(&mut f, v, 23, fields)), not_found(v));
            let fields = (0..33).map(|i| uid(v, &format!("missing-{i}"))).collect();
            let query = || vec![Node::enumeration(QUERY_FUNCTION, 1)];
            let response =
                f.e.process(
                    "owner",
                    &message(
                        v,
                        vec![(24, query()), (23, fields), (24, query())],
                        vec![Node::enumeration(
                            BATCH_ERROR_CONTINUATION_OPTION,
                            continuation,
                        )],
                    ),
                )
                .unwrap();
            let items: Vec<_> = response.all(BATCH_ITEM).collect();
            let expected = match continuation {
                1 => vec![0, 1, 0],
                2 => vec![0, 1],
                _ => vec![3, 1],
            };
            assert_eq!(
                items
                    .iter()
                    .map(|i| i.required(RESULT_STATUS).unwrap().number().unwrap())
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(items[1].required(OPERATION).unwrap().number().unwrap(), 23);
            assert_eq!(
                items[1].required(RESULT_REASON).unwrap().number().unwrap(),
                if v.0 >= 2 { 0x3a } else { 0x100 }
            );
            assert!(items[1].get(RESPONSE_PAYLOAD).is_none());
            for (index, item) in items.iter().enumerate() {
                assert_eq!(
                    item.required(OPERATION).unwrap().number().unwrap(),
                    [24, 23, 24][index]
                );
                if v.0 < 3 {
                    assert_eq!(
                        item.required(UNIQUE_BATCH_ITEM_ID)
                            .unwrap()
                            .byte_string()
                            .unwrap(),
                        &[index as u8]
                    );
                }
            }
            let path = f._dir.path().join("store");
            drop(f.e);
            let store = Store::open(&path, &f._dir.path().join("master")).unwrap();
            store.verify_audit().unwrap();
            assert!(store.list("owner").unwrap().is_empty());
            let conn = rusqlite::Connection::open(&path).unwrap();
            let rows = conn
                .prepare("SELECT operation,status FROM audit ORDER BY seq")
                .unwrap()
                .query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut expected_rows = vec![(23, 1)];
            expected_rows.extend(
                expected
                    .into_iter()
                    .enumerate()
                    .map(|(i, status)| ([24, 23, 24][i], status)),
            );
            assert_eq!(rows, expected_rows);
        }
    }
}
#[test]
fn all_editions_validate_inline_stored_mixed_unordered_and_duplicate_chains() {
    let p = Pki::new();
    for v in versions() {
        let mut f = Fixture::new(Some(&p.root));
        for chain in [
            vec![cert(&p.leaf), cert(&p.intermediate)],
            vec![cert(&p.root), cert(&p.intermediate), cert(&p.leaf)],
            vec![
                cert(&p.intermediate),
                cert(&p.leaf),
                cert(&p.root),
                cert(&p.leaf),
            ],
        ] {
            assert_eq!(validity(&call(&mut f, v, 23, chain)), 1);
        }
        let leaf = register(&mut f, v, &p.leaf);
        let inter = register(&mut f, v, &p.intermediate);
        assert_eq!(
            validity(&call(
                &mut f,
                v,
                23,
                vec![uid(v, &inter), cert(&p.root), uid(v, &leaf)]
            )),
            1
        );
        assert_eq!(
            validity(&call(&mut f, v, 23, vec![uid(v, &leaf), uid(v, &inter)])),
            1
        );
        assert!(keytend_kmip_server::protocol::operations(v).contains(&23));
    }
}
// REQ:a5ee21f4d954459b a Validity Date is checked against every certificate of the chain
// REQ:a43730a96b3c8809 without a Validity Date the chain is checked at the current time
#[test]
fn trust_date_and_whole_chain_are_enforced() {
    let p = Pki::new();
    for v in versions() {
        let mut f = Fixture::new(Some(&p.root));
        let chain = vec![cert(&p.leaf), cert(&p.intermediate)];
        for at in [p.at - 1001, p.at + 1001, i64::MIN, i64::MAX] {
            let mut fields = chain.clone();
            fields.push(Node::date(VALIDITY_DATE, at));
            assert_eq!(validity(&call(&mut f, v, 23, fields)), 2);
        }
        let mut fields = chain.clone();
        fields.push(Node::date(VALIDITY_DATE, p.at));
        assert_eq!(validity(&call(&mut f, v, 23, fields)), 1);
        // Omitted: the current time, inside the certificates' window.
        assert_eq!(validity(&call(&mut f, v, 23, chain.clone())), 1);
        assert_eq!(validity(&call(&mut f, v, 23, vec![cert(&p.leaf)])), 2);
        assert_eq!(validity(&call(&mut f, v, 23, vec![cert(&p.other)])), 2);
        let mut extra = chain.clone();
        extra.push(cert(&p.other));
        assert_eq!(validity(&call(&mut f, v, 23, extra)), 2);
        let mut f = Fixture::new(None);
        assert_eq!(validity(&call(&mut f, v, 23, chain)), 3);
    }
}
#[test]
fn malformed_inputs_and_bounds_never_report_valid() {
    let p = Pki::new();
    let v = Version(2, 1);
    let mut f = Fixture::new(Some(&p.root));
    for fields in [
        vec![],
        vec![Node::date(VALIDITY_DATE, p.at)],
        vec![cert(&p.leaf), Node::int(VALIDITY_DATE, 1)],
        vec![
            cert(&p.leaf),
            Node::date(VALIDITY_DATE, p.at),
            Node::date(VALIDITY_DATE, p.at),
        ],
        vec![structure(
            CERTIFICATE,
            vec![
                Node::int(CERTIFICATE_TYPE, 1),
                Node::bytes(CERTIFICATE_VALUE, p.leaf.to_der().unwrap()),
            ],
        )],
        vec![structure(
            CERTIFICATE,
            vec![
                Node::enumeration(CERTIFICATE_TYPE, 1),
                Node::bytes(CERTIFICATE_VALUE, vec![1, 2, 3]),
            ],
        )],
    ] {
        assert_eq!(reason(&call(&mut f, v, 23, fields)), 7);
    }
    let mut trailing = p.leaf.to_der().unwrap();
    trailing.push(0);
    assert_eq!(
        reason(&call(
            &mut f,
            v,
            23,
            vec![structure(
                CERTIFICATE,
                vec![
                    Node::enumeration(CERTIFICATE_TYPE, 1),
                    Node::bytes(CERTIFICATE_VALUE, trailing)
                ]
            )]
        )),
        7
    );
    assert_eq!(
        reason(&call(
            &mut f,
            v,
            23,
            (0..33).map(|_| cert(&p.leaf)).collect()
        )),
        0x3a
    );
    let pgp = structure(
        CERTIFICATE,
        vec![
            Node::enumeration(CERTIFICATE_TYPE, 2),
            Node::bytes(CERTIFICATE_VALUE, vec![1]),
        ],
    );
    assert_eq!(reason(&call(&mut f, v, 23, vec![pgp])), 8);
}
#[test]
fn stored_certificate_permissions_archive_revoke_destroy_and_fresh() {
    let p = Pki::new();
    for v in versions() {
        let mut f = Fixture::new(Some(&p.root));
        let leaf = register(&mut f, v, &p.leaf);
        let inter = register(&mut f, v, &p.intermediate);
        let fields = vec![uid(v, &leaf), uid(v, &inter)];
        let foreign =
            f.e.process("other", &message(v, vec![(23, fields.clone())], vec![]))
                .unwrap();
        assert_eq!(reason(&foreign), not_found(v));
        let denied =
            f.e.process_authorized(
                "owner",
                &message(v, vec![(23, fields.clone())], vec![]),
                Some(&[10]),
            )
            .unwrap();
        assert_eq!(reason(&denied), 12);
        assert_eq!(validity(&call(&mut f, v, 23, fields.clone())), 1);
        let obj = f.e.store.get("owner", &leaf).unwrap().unwrap();
        assert_eq!(obj.metadata.fresh, Some(true));
        body(&call(&mut f, v, 21, vec![uid(v, &leaf)]));
        assert_eq!(reason(&call(&mut f, v, 23, fields.clone())), 13);
        body(&call(&mut f, v, 22, vec![uid(v, &leaf)]));
        let revoke = structure(
            REVOCATION_REASON,
            vec![Node::enumeration(REVOCATION_REASON_CODE, 2)],
        );
        let mut revoke_fields = vec![uid(v, &leaf), revoke];
        if v < Version(1, 3) {
            revoke_fields.push(Node::date(
                COMPROMISE_OCCURRENCE_DATE,
                keytend_kmip_server::store::now(),
            ));
        }
        body(&call(&mut f, v, 19, revoke_fields));
        assert_eq!(validity(&call(&mut f, v, 23, fields.clone())), 2);
        body(&call(&mut f, v, 20, vec![uid(v, &leaf)]));
        assert_eq!(reason(&call(&mut f, v, 23, fields)), 12);
    }
}
#[test]
fn non_certificate_ids_have_versioned_errors_and_no_implicit_placeholder() {
    let p = Pki::new();
    for v in versions() {
        let mut f = Fixture::new(Some(&p.root));
        let a = vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        ];
        let attrs = if v.0 == 1 {
            structure(
                TEMPLATE_ATTRIBUTE,
                a.into_iter()
                    .map(|mut n| {
                        let name = if n.tag == CRYPTOGRAPHIC_ALGORITHM {
                            "Cryptographic Algorithm"
                        } else {
                            "Cryptographic Length"
                        };
                        n.tag = ATTRIBUTE_VALUE;
                        structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), n])
                    })
                    .collect(),
            )
        } else {
            structure(ATTRIBUTES, a)
        };
        let id = body(&call(
            &mut f,
            v,
            1,
            vec![Node::enumeration(OBJECT_TYPE, 2), attrs],
        ))
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
        assert_eq!(
            reason(&call(&mut f, v, 23, vec![uid(v, &id)])),
            if v.0 >= 2 { 0x30 } else { 7 }
        );
        assert_eq!(
            reason(&call(&mut f, v, 23, vec![uid(v, "missing")])),
            not_found(v)
        );
        // 1.x Validate table (1.4 Table 351): no certificate list is Invalid Message.
        assert_eq!(
            reason(&call(&mut f, v, 23, vec![])),
            if v.0 == 1 { 4 } else { 7 }
        );
    }
}
#[test]
fn repeated_batch_references_validate_one_chain_and_keep_placeholder() {
    let p = Pki::new();
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new(Some(&p.root));
        let inter = register(&mut f, v, &p.intermediate);
        let request = message(
            v,
            vec![
                (
                    3,
                    vec![
                        Node::enumeration(OBJECT_TYPE, 1),
                        attributes(v, certificate_required(&p.leaf)),
                        cert(&p.leaf),
                    ],
                ),
                (
                    23,
                    vec![Node::enumeration(UNIQUE_IDENTIFIER, 12), uid(v, &inter)],
                ),
                (
                    10,
                    if v.0 >= 3 {
                        vec![Node::enumeration(UNIQUE_IDENTIFIER, 1)]
                    } else {
                        vec![]
                    },
                ),
            ],
            vec![],
        );
        let response = f.e.process("owner", &request).unwrap();
        let items = response.all(BATCH_ITEM).collect::<Vec<_>>();
        assert_eq!(items.len(), 3);
        assert!(
            items
                .iter()
                .all(|i| i.required(RESULT_STATUS).unwrap().number().unwrap() == 0),
            "{}",
            serde_json::to_string(&response).unwrap()
        );
        assert_eq!(
            items[1]
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .required(VALIDITY_INDICATOR)
                .unwrap()
                .number()
                .unwrap(),
            1
        );
        let id = items[0]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        assert_eq!(
            items[2]
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            id
        );
    }
}
#[test]
fn trust_bundle_is_bounded_exact_and_has_no_ambient_roots() {
    let p = Pki::new();
    let pem = p.root.to_pem().unwrap();
    assert!(CertificateValidation::from_pem(&pem).is_ok());
    for bad in [
        vec![],
        b"garbage".to_vec(),
        [pem.clone(), b"garbage".to_vec()].concat(),
        [pem.clone(), pem.clone()].concat(),
        b"-----BEGIN CERTIFICATE-----".to_vec(),
        vec![0; 1024 * 1024 + 1],
    ] {
        assert!(CertificateValidation::from_pem(&bad).is_err());
    }
    assert_eq!(
        CertificateValidation::default()
            .validate(&[p.root], p.at)
            .unwrap(),
        3
    );
}

#[test]
fn cryptographic_path_constraints_and_self_issued_rollover_are_verified() {
    let at = now();
    let (root, key) = issue("root", 1, None, true, at - 10000, at + 10000);
    let (inter, ikey) = issue(
        "bad-issuer",
        2,
        Some((&root, &key)),
        false,
        at - 10000,
        at + 10000,
    );
    let (leaf, _) = issue(
        "leaf",
        3,
        Some((&inter, &ikey)),
        false,
        at - 1000,
        at + 1000,
    );
    let policy = CertificateValidation::from_pem(&root.to_pem().unwrap()).unwrap();
    assert_eq!(policy.validate(&[leaf, inter.clone()], at).unwrap(), 2);
    let (leaf, _) = issue("leaf", 4, Some((&root, &key)), false, at - 1000, at + 1000);
    let mut corrupt = leaf.to_der().unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(
        policy
            .validate(&[X509::from_der(&corrupt).unwrap()], at)
            .unwrap(),
        2
    );
    let (rollover, rkey) = issue("root", 5, Some((&root, &key)), true, at - 5000, at + 5000);
    let (leaf, _) = issue(
        "leaf",
        6,
        Some((&rollover, &rkey)),
        false,
        at - 1000,
        at + 1000,
    );
    assert_eq!(policy.validate(&[rollover, root, leaf], at).unwrap(), 1);
}

#[test]
fn draft_named_chain_references_and_missing_nested_fields() {
    let p = Pki::new();
    let v = Version(3, 0);
    let mut f = Fixture::new(Some(&p.root));
    for (name, c) in [("leaf", &p.leaf), ("intermediate", &p.intermediate)] {
        body(&call(
            &mut f,
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 1),
                structure(
                    ATTRIBUTES,
                    certificate_required(c)
                        .into_iter()
                        .chain([Node::text(NAME, name)])
                        .collect(),
                ),
                cert(c),
            ],
        ));
    }
    assert_eq!(
        validity(&call(
            &mut f,
            v,
            23,
            vec![
                Node::name_reference(UNIQUE_IDENTIFIER, "intermediate"),
                Node::name_reference(UNIQUE_IDENTIFIER, "leaf")
            ]
        )),
        1
    );
    for v in versions() {
        for fields in [
            vec![Node::enumeration(CERTIFICATE_TYPE, 1)],
            vec![Node::bytes(CERTIFICATE_VALUE, p.leaf.to_der().unwrap())],
        ] {
            assert_eq!(
                reason(&call(&mut f, v, 23, vec![structure(CERTIFICATE, fields)])),
                7
            );
        }
    }
}

fn attributes(v: Version, attrs: Vec<Node>) -> Node {
    if v.0 == 1 {
        structure(
            TEMPLATE_ATTRIBUTE,
            attrs
                .into_iter()
                .map(|mut a| {
                    let name = match a.tag {
                        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
                        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
                        CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
                        CERTIFICATE_TYPE => "Certificate Type",
                        CERTIFICATE_LENGTH => "Certificate Length",
                        DIGITAL_SIGNATURE_ALGORITHM => "Digital Signature Algorithm",
                        _ => tag_name(a.tag).expect("test attribute"),
                    };
                    a.tag = ATTRIBUTE_VALUE;
                    structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), a])
                })
                .collect(),
        )
    } else {
        structure(ATTRIBUTES, attrs)
    }
}
fn read_metadata(f: &mut Fixture, v: Version, id: &str) -> Vec<Node> {
    let response = call(f, v, 11, vec![uid(v, id)]);
    let p = body(&response);
    if v.0 == 1 {
        p.all(ATTRIBUTE)
            .filter_map(|a| {
                let tag = match a.required(ATTRIBUTE_NAME).unwrap().string().unwrap() {
                    "Cryptographic Algorithm" => CRYPTOGRAPHIC_ALGORITHM,
                    "Cryptographic Length" => CRYPTOGRAPHIC_LENGTH,
                    "Certificate Type" => CERTIFICATE_TYPE,
                    "Certificate Length" => CERTIFICATE_LENGTH,
                    "Digital Signature Algorithm" => DIGITAL_SIGNATURE_ALGORITHM,
                    _ => return None,
                };
                assert!(
                    a.get(ATTRIBUTE_INDEX).is_none(),
                    "X509 certificate metadata is single valued"
                );
                let mut value = a.required(ATTRIBUTE_VALUE).unwrap().clone();
                value.tag = tag;
                Some(value)
            })
            .collect()
    } else {
        p.required(ATTRIBUTES).unwrap().children().unwrap().to_vec()
    }
}
#[test]
fn certificate_metadata_distinguishes_subject_from_issuer_and_bytes_from_bits() {
    let p = Pki::new();
    // RSA issuer signs an EC subject. The certificate's own public-key algorithm
    // must remain EC while the issuer's signature is SHA-384 with RSA.
    let issuer = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(700).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(p.leaf.subject_name()).unwrap();
    b.set_issuer_name(p.root.subject_name()).unwrap();
    b.set_pubkey(&p.leaf.public_key().unwrap()).unwrap();
    b.set_not_before(&Asn1Time::from_unix(p.at - 10).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(p.at + 10).unwrap())
        .unwrap();
    b.sign(&issuer, MessageDigest::sha384()).unwrap();
    let c = b.build();
    let der = c.to_der().unwrap();
    let inspected = keytend_kmip_server::crypto::certificate::inspect(&der).unwrap();
    assert_eq!(inspected.algorithm, 26);
    assert_eq!(inspected.bits, 256);
    assert_eq!(inspected.signature, Some(6));
    for v in versions() {
        let mut f = Fixture::new(None);
        let id = register(&mut f, v, &c);
        let attrs = read_metadata(&mut f, v, &id);
        assert!(attrs.contains(&Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6)));
        assert!(attrs.contains(&Node::int(CRYPTOGRAPHIC_LENGTH, 256)));
        assert!(attrs.contains(&Node::enumeration(CERTIFICATE_TYPE, 1)));
        if v >= Version(1, 1) {
            assert!(attrs.contains(&Node::int(CERTIFICATE_LENGTH, der.len() as i32)));
            assert!(attrs.contains(&Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 6)));
        } else {
            assert!(
                !attrs
                    .iter()
                    .any(|a| matches!(a.tag, CERTIFICATE_LENGTH | DIGITAL_SIGNATURE_ALGORITHM))
            );
        }
        let fetched = call(&mut f, v, 10, vec![uid(v, &id)]);
        assert_eq!(
            body(&fetched)
                .required(CERTIFICATE)
                .unwrap()
                .required(CERTIFICATE_VALUE)
                .unwrap()
                .byte_string()
                .unwrap(),
            der
        );
    }
}
#[test]
fn certificate_metadata_is_derived_and_conflicts_or_duplicate_signatures_are_rejected() {
    let p = Pki::new();
    let der = p.leaf.to_der().unwrap();
    for v in versions().into_iter().filter(|v| *v >= Version(1, 1)) {
        let mut f = Fixture::new(None);
        let base = vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
            Node::int(CERTIFICATE_LENGTH, der.len() as i32),
        ];
        for wrong in [
            Node::int(CERTIFICATE_LENGTH, der.len() as i32 + 1),
            Node::enumeration(CERTIFICATE_TYPE, 2),
            Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 5),
            Node::int(CRYPTOGRAPHIC_LENGTH, 255),
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
            Node::int(CRYPTOGRAPHIC_ALGORITHM, 6),
        ] {
            let mut attrs = base.clone();
            attrs.retain(|a| a.tag != wrong.tag);
            attrs.push(wrong);
            assert_eq!(
                reason(&call(
                    &mut f,
                    v,
                    3,
                    vec![
                        Node::enumeration(OBJECT_TYPE, 1),
                        attributes(v, attrs),
                        cert(&p.leaf)
                    ]
                )),
                7
            );
        }
        let mut attrs = base.clone();
        attrs.extend([
            Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 14),
            Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 14),
        ]);
        assert_eq!(
            reason(&call(
                &mut f,
                v,
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 1),
                    attributes(v, attrs),
                    cert(&p.leaf)
                ]
            )),
            if v.0 >= 2 { 0x23 } else { 7 }
        );
        let mut trailing = der.clone();
        trailing.push(0);
        assert_eq!(
            reason(&call(
                &mut f,
                v,
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 1),
                    attributes(v, base),
                    structure(
                        CERTIFICATE,
                        vec![
                            Node::enumeration(CERTIFICATE_TYPE, 1),
                            Node::bytes(CERTIFICATE_VALUE, trailing)
                        ]
                    )
                ]
            )),
            7
        );
    }
    for v in [Version(1, 2), Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new(None);
        // Server-set metadata is derived when the client omits it (BL-M-10).
        let response = call(
            &mut f,
            v,
            3,
            vec![Node::enumeration(OBJECT_TYPE, 1), cert(&p.leaf)],
        );
        let id = body(&response)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let attrs = read_metadata(&mut f, v, &id);
        assert!(attrs.contains(&Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 26)));
        assert!(attrs.contains(&Node::int(CERTIFICATE_LENGTH, der.len() as i32)));
        let response = call(
            &mut f,
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 1),
                cert(&p.leaf),
                attributes(
                    v,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 26),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
                        Node::int(CERTIFICATE_LENGTH, der.len() as i32),
                    ],
                ),
            ],
        );
        let id = body(&response)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        let attrs = read_metadata(&mut f, v, id);
        assert!(attrs.contains(&Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 26)));
        assert!(attrs.contains(&Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 14)));
    }
}

#[test]
fn certificate_metadata_survives_import_destroy_restart_and_clean_backup_restore() {
    let p = Pki::new();
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new(None);
        let id = register(&mut f, v, &p.leaf);
        let before = read_metadata(&mut f, v, &id);
        let exported = body(&call(&mut f, v, 43, vec![uid(v, &id)]))
            .children()
            .unwrap()
            .to_vec();
        let mut fields = exported.clone();
        fields.push(Node::boolean(REPLACE_EXISTING, true));
        body(&call(&mut f, v, 42, fields));
        let metadata_only = |attrs: Vec<Node>| {
            attrs
                .into_iter()
                .filter(|a| {
                    matches!(
                        a.tag,
                        CERTIFICATE_TYPE
                            | CERTIFICATE_LENGTH
                            | CRYPTOGRAPHIC_ALGORITHM
                            | CRYPTOGRAPHIC_LENGTH
                            | DIGITAL_SIGNATURE_ALGORITHM
                    )
                })
                .collect::<Vec<_>>()
        };
        assert!(metadata_only(before.clone()) == metadata_only(read_metadata(&mut f, v, &id)));
        let path = f._dir.path().join("backup");
        f.e.store.backup(&path).unwrap();
        let clean = f._dir.path().join("clean");
        std::fs::create_dir(&clean).unwrap();
        let db = clean.join("store");
        std::fs::copy(path, &db).unwrap();
        f.e = Engine::new(
            Store::open(&db, &f._dir.path().join("master")).unwrap(),
            true,
        );
        assert!(metadata_only(before.clone()) == metadata_only(read_metadata(&mut f, v, &id)));
        body(&call(&mut f, v, 20, vec![uid(v, &id)]));
        assert!(metadata_only(before.clone()) == metadata_only(read_metadata(&mut f, v, &id)));
        let mut destroyed = body(&call(&mut f, v, 43, vec![uid(v, &id)]))
            .children()
            .unwrap()
            .to_vec();
        assert!(
            destroyed
                .iter()
                .find(|a| a.tag == CERTIFICATE)
                .unwrap()
                .get(CERTIFICATE_VALUE)
                .is_none()
        );
        destroyed.push(Node::boolean(REPLACE_EXISTING, true));
        body(&call(&mut f, v, 42, destroyed));
        assert!(metadata_only(before) == metadata_only(read_metadata(&mut f, v, &id)));
    }
}
#[test]
fn historic_certificate_metadata_uses_actual_material_and_locate_and_is_immutable() {
    let p = Pki::new();
    let v = Version(2, 1);
    let mut f = Fixture::new(None);
    let id = register(&mut f, v, &p.leaf);
    let mut historic = f.e.store.get("owner", &id).unwrap().unwrap();
    historic.algorithm = 0;
    historic.bits = 0;
    historic.attrs.retain(|a| {
        !matches!(
            a.tag,
            CERTIFICATE_TYPE
                | CERTIFICATE_LENGTH
                | CRYPTOGRAPHIC_ALGORITHM
                | CRYPTOGRAPHIC_LENGTH
                | DIGITAL_SIGNATURE_ALGORITHM
        )
    });
    f.e.store.put(&historic).unwrap();
    let located = call(
        &mut f,
        v,
        8,
        vec![structure(
            ATTRIBUTES,
            vec![
                Node::int(CERTIFICATE_LENGTH, p.leaf.to_der().unwrap().len() as i32),
                Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 14),
            ],
        )],
    );
    assert!(
        body(&located)
            .all(UNIQUE_IDENTIFIER)
            .any(|a| a.identifier_text().unwrap() == id)
    );
    let restored = read_metadata(&mut f, v, &id);
    assert!(restored.contains(&Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 26)));
    for tag in [
        CERTIFICATE_TYPE,
        CERTIFICATE_LENGTH,
        DIGITAL_SIGNATURE_ALGORITHM,
    ] {
        assert_eq!(
            reason(&call(
                &mut f,
                v,
                15,
                vec![uid(v, &id), Node::enumeration(ATTRIBUTE_REFERENCE, tag)]
            )),
            0x22
        );
    }
    let legacy = Version(1, 1);
    assert_eq!(
        reason(&call(
            &mut f,
            legacy,
            11,
            vec![
                uid(legacy, &id),
                Node::text(ATTRIBUTE_NAME, "Cryptographic Algorithm")
            ]
        )),
        8
    );
    body(&call(
        &mut f,
        legacy,
        11,
        vec![
            uid(legacy, &id),
            Node::text(ATTRIBUTE_NAME, "Certificate Length"),
        ],
    ));
    // Unrepresentable EC metadata must not prevent byte-preserving Get.
    body(&call(&mut f, legacy, 10, vec![uid(legacy, &id)]));
}
#[test]
fn rsa_sha3_certificate_signature_mapping_is_versioned_without_trust_claims() {
    let key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut n = X509NameBuilder::new().unwrap();
    n.append_entry_by_text("CN", "metadata-only").unwrap();
    let name = n.build();
    for (md, expected) in [
        (MessageDigest::sha256(), 5),
        (MessageDigest::sha384(), 6),
        (MessageDigest::sha512(), 7),
        (MessageDigest::sha3_256(), 17),
        (MessageDigest::sha3_384(), 18),
        (MessageDigest::sha3_512(), 19),
    ] {
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(
            &BigNum::from_u32(expected)
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::from_unix(1).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::from_unix(2).unwrap()).unwrap();
        b.sign(&key, md).unwrap();
        let c = b.build();
        let der = c.to_der().unwrap();
        let inspected = keytend_kmip_server::crypto::certificate::inspect(&der).unwrap();
        assert_eq!(inspected.algorithm, 4);
        assert_eq!(inspected.bits, 2048);
        assert_eq!(inspected.signature, Some(expected));
        for v in [
            Version(1, 1),
            Version(1, 3),
            Version(1, 4),
            Version(2, 1),
            Version(3, 0),
        ] {
            let mut f = Fixture::new(None);
            let response = call(
                &mut f,
                v,
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 1),
                    cert(&c),
                    attributes(
                        v,
                        vec![
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
                            Node::int(CERTIFICATE_LENGTH, der.len() as i32),
                        ],
                    ),
                ],
            );
            if expected >= 17 && v < Version(1, 4) {
                assert_eq!(reason(&response), 7);
            } else {
                let id = body(&response)
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap();
                assert!(
                    read_metadata(&mut f, v, id)
                        .contains(&Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, expected))
                );
            }
        }
    }
}

fn certificate_required(c: &X509) -> Vec<Node> {
    vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
        Node::int(CERTIFICATE_LENGTH, c.to_der().unwrap().len() as i32),
    ]
}
#[test]
fn certificate_register_derives_server_set_attributes_and_never_inserts_invalid_objects() {
    let p = Pki::new();
    for v in versions().into_iter().filter(|v| *v >= Version(1, 1)) {
        let mut f = Fixture::new(None);
        let required = certificate_required(&p.leaf);
        let mut registered = 0;
        for missing in [
            CRYPTOGRAPHIC_ALGORITHM,
            CRYPTOGRAPHIC_LENGTH,
            CRYPTOGRAPHIC_USAGE_MASK,
            CERTIFICATE_LENGTH,
        ] {
            // The attribute rules make these server-set (or, for the Usage
            // Mask, server-or-client set), so omission is accepted, except
            // that 1.0/1.1 cannot derive an EC certificate's purpose.
            let attrs = required
                .iter()
                .filter(|a| a.tag != missing)
                .cloned()
                .collect();
            let response = call(
                &mut f,
                v,
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 1),
                    attributes(v, attrs),
                    cert(&p.leaf),
                ],
            );
            if missing == CRYPTOGRAPHIC_ALGORITHM && v < Version(1, 2) {
                assert_eq!(reason(&response), 6);
            } else {
                let id = body(&response)
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap()
                    .to_owned();
                registered += 1;
                let metadata = read_metadata(&mut f, v, &id);
                for derived in &required {
                    if derived.tag == CRYPTOGRAPHIC_ALGORITHM && missing == derived.tag {
                        // An EC key without a declared purpose is typed EC (1.2+).
                        assert!(metadata.contains(&Node::enumeration(derived.tag, 26)));
                    } else if derived.tag != CRYPTOGRAPHIC_USAGE_MASK {
                        assert!(metadata.contains(derived));
                    }
                }
                if missing == CRYPTOGRAPHIC_USAGE_MASK && v.0 >= 2 {
                    // An omitted Usage Mask grants no cryptographic use.
                    assert!(metadata.contains(&Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0)));
                }
            }
            let attrs = required
                .iter()
                .map(|a| {
                    if a.tag == missing {
                        Node::text(missing, "invalid type")
                    } else {
                        a.clone()
                    }
                })
                .collect();
            assert_eq!(
                reason(&call(
                    &mut f,
                    v,
                    3,
                    vec![
                        Node::enumeration(OBJECT_TYPE, 1),
                        attributes(v, attrs),
                        cert(&p.leaf)
                    ]
                )),
                7
            );
            assert_eq!(f.e.store.list("owner").unwrap().len(), registered);
        }
    }
}

#[test]
fn destroyed_certificate_import_cannot_invent_missing_or_conflicting_metadata() {
    let p = Pki::new();
    let v = Version(2, 1);
    let mut f = Fixture::new(None);
    let id = register(&mut f, v, &p.leaf);
    body(&call(&mut f, v, 20, vec![uid(v, &id)]));
    let exported = body(&call(&mut f, v, 43, vec![uid(v, &id)]))
        .children()
        .unwrap()
        .to_vec();
    for tag in [
        CRYPTOGRAPHIC_ALGORITHM,
        CRYPTOGRAPHIC_LENGTH,
        CRYPTOGRAPHIC_USAGE_MASK,
        CERTIFICATE_TYPE,
        CERTIFICATE_LENGTH,
        DIGITAL_SIGNATURE_ALGORITHM,
    ] {
        for omit in [true, false] {
            let mut fields = exported.clone();
            let attrs = fields.iter_mut().find(|a| a.tag == ATTRIBUTES).unwrap();
            if let keytend_kmip_server::ttlv::Value::Structure(values) = &mut attrs.value {
                values.retain(|a| a.tag != tag);
                if !omit {
                    values.push(Node::text(tag, "invalid metadata"));
                }
            }
            fields.push(Node::boolean(REPLACE_EXISTING, true));
            assert_eq!(
                reason(&call(&mut f, v, 42, fields)),
                if omit && v.0 == 1 { 6 } else { 7 }
            );
        }
    }
    let metadata = read_metadata(&mut f, v, &id);
    assert!(metadata.contains(&Node::enumeration(CERTIFICATE_TYPE, 1)));
}

fn identity_certificate(empty: bool) -> X509 {
    use openssl::asn1::{Asn1Object, Asn1OctetString};
    use openssl::x509::{X509Extension, X509Name};
    let key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut issuer = X509NameBuilder::new().unwrap();
    issuer.append_entry_by_text("CN", "issuer").unwrap();
    issuer.append_entry_by_text("OU", "first").unwrap();
    issuer.append_entry_by_text("OU", "second").unwrap();
    let issuer = issuer.build();
    // A single multi-valued RDN, preserving the actual SET rather than flattening.
    let grouped = X509Name::from_der(
        &hex::decode("30163114300806035504030c01613008060355040b0c0162").unwrap(),
    )
    .unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject
        .append_entry_by_text("CN", " #é,plus+slash\\nul\0 ")
        .unwrap();
    subject
        .append_entry_by_text("emailAddress", "test@example.org")
        .unwrap();
    subject
        .append_entry_by_text("serialNumber", "subject-serial")
        .unwrap();
    let subject = if empty {
        X509Name::from_der(&[0x30, 0]).unwrap()
    } else {
        let suffix = subject.build().to_der().unwrap();
        let offset = if suffix[1] < 128 {
            2
        } else {
            2 + (suffix[1] & 127) as usize
        };
        let mut content = grouped.to_der().unwrap()[2..].to_vec();
        content.extend_from_slice(&suffix[offset..]);
        assert!(content.len() < 256);
        let mut encoded = if content.len() < 128 {
            vec![0x30, content.len() as u8]
        } else {
            vec![0x30, 0x81, content.len() as u8]
        };
        encoded.extend(content);
        X509Name::from_der(&encoded).unwrap()
    };
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&subject).unwrap();
    b.set_issuer_name(&issuer).unwrap();
    b.set_pubkey(&key).unwrap();
    let mut serial = vec![0x80; 20];
    serial[19] = 1;
    b.set_serial_number(
        &BigNum::from_slice(&serial)
            .unwrap()
            .to_asn1_integer()
            .unwrap(),
    )
    .unwrap();
    b.set_not_before(&Asn1Time::from_unix(now() - 10).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(now() + 1000).unwrap())
        .unwrap();
    // Independent literal GeneralNames: DNS, email and IPv4.
    let alternatives = hex::decode("30138205612e6f726781046140626387047f000001").unwrap();
    for (oid, critical) in [("2.5.29.17", true), ("2.5.29.18", false)] {
        b.append_extension(
            X509Extension::new_from_der(
                &Asn1Object::from_str(oid).unwrap(),
                critical,
                &Asn1OctetString::new_from_bytes(&alternatives).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    }
    b.sign(&key, MessageDigest::sha256()).unwrap();
    b.build()
}
fn identity_attrs(f: &mut Fixture, v: Version, id: &str) -> Vec<Node> {
    let response = call(f, v, 11, vec![uid(v, id)]);
    let p = body(&response);
    if v.0 >= 2 {
        return p.required(ATTRIBUTES).unwrap().children().unwrap().to_vec();
    }
    p.all(ATTRIBUTE)
        .map(|a| {
            let name = a.required(ATTRIBUTE_NAME).unwrap().string().unwrap();
            let tag = (0x420000..=0x420200)
                .find(|t| tag_name(*t) == Some(name))
                .unwrap();
            let mut value = a.required(ATTRIBUTE_VALUE).unwrap().clone();
            value.tag = tag;
            value
        })
        .collect()
}
fn identity_tag(tag: u32) -> bool {
    matches!(
        tag,
        X_509_CERTIFICATE_IDENTIFIER
            | X_509_CERTIFICATE_ISSUER
            | X_509_CERTIFICATE_SUBJECT
            | CERTIFICATE_IDENTIFIER
            | CERTIFICATE_SUBJECT
            | CERTIFICATE_ISSUER
            | CERTIFICATE_SUBJECT_CN
            ..=CERTIFICATE_ISSUER_DN_QUALIFIER | CERTIFICATE_SUBJECT_DN | CERTIFICATE_ISSUER_DN
    )
}
#[test]
fn x509_identity_preserves_der_serial_and_names_and_nul() {
    let c = identity_certificate(false);
    let m =
        keytend_kmip_server::crypto::certificate_attributes::inspect(&c.to_der().unwrap()).unwrap();
    let mut serial = vec![2, 21, 0];
    serial.extend([0x80; 19]);
    serial.push(1);
    assert_eq!(m.serial, serial);
    assert_eq!(m.issuer, c.issuer_name().to_der().unwrap());
    assert_eq!(m.subject, c.subject_name().to_der().unwrap());
    assert_eq!(
        m.subject_alternatives,
        vec![
            hex::decode("8205612e6f7267").unwrap(),
            hex::decode("810461406263").unwrap(),
            hex::decode("87047f000001").unwrap()
        ]
    );
    assert_eq!(m.issuer_alternatives, m.subject_alternatives);
    assert!(
        m.fields
            .contains(&(CERTIFICATE_SUBJECT_CN, " #é,plus+slash\\nul\0 ".to_owned()))
    );
    assert_eq!(
        m.fields
            .iter()
            .filter(|(t, _)| *t == CERTIFICATE_ISSUER_OU)
            .count(),
        2
    );
    assert!(m.subject_text.contains("CN=a+OU=b"));
    assert!(m.subject_text.contains("\\00"));
    assert!(m.subject_text.contains("\\,"));
    assert_eq!(m.issuer_text, "OU=second,OU=first,CN=issuer");
}
#[test]
fn x509_identity_is_versioned_readonly_and_locatable() {
    let c = identity_certificate(false);
    for v in versions() {
        let mut f = Fixture::new(None);
        let id = register(&mut f, v, &c);
        let attrs = identity_attrs(&mut f, v, &id);
        assert_eq!(
            attrs.iter().any(|a| a.tag == X_509_CERTIFICATE_IDENTIFIER),
            v >= Version(1, 1)
        );
        assert_eq!(
            attrs.iter().any(|a| a.tag == CERTIFICATE_IDENTIFIER),
            v.0 == 1
        );
        assert_eq!(
            attrs
                .iter()
                .filter(|a| a.tag == CERTIFICATE_SUBJECT_CN)
                .count(),
            if v.0 >= 2 { 2 } else { 0 }
        );
        assert_eq!(
            attrs.iter().any(|a| a.tag == CERTIFICATE_SUBJECT_DN),
            v.0 >= 3
        );
        for a in attrs.into_iter().filter(|a| identity_tag(a.tag)) {
            let filter = if v.0 == 1 {
                attributes(v, vec![a.clone()]).children().unwrap()[0].clone()
            } else {
                structure(ATTRIBUTES, vec![a.clone()])
            };
            assert!(
                body(&call(&mut f, v, 8, vec![filter]))
                    .all(UNIQUE_IDENTIFIER)
                    .any(|n| n.identifier_text().unwrap() == id)
            );
            let update = if v.0 == 1 {
                attributes(v, vec![a.clone()]).children().unwrap()[0].clone()
            } else {
                structure(NEW_ATTRIBUTE, vec![a.clone()])
            };
            assert_eq!(
                reason(&call(&mut f, v, 13, vec![uid(v, &id), update])),
                if v.0 >= 2 { 0x22 } else { 12 }
            );
        }
    }
}
#[test]
fn x509_identity_import_conflicts_fail_atomically_and_recovery_is_exact() {
    let c = identity_certificate(false);
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new(None);
        let id = register(&mut f, v, &c);
        let before = identity_attrs(&mut f, v, &id)
            .into_iter()
            .filter(|a| identity_tag(a.tag))
            .collect::<Vec<_>>();
        let mut exported = body(&call(&mut f, v, 43, vec![uid(v, &id)]))
            .children()
            .unwrap()
            .to_vec();
        body(&call(&mut f, v, 20, vec![uid(v, &id)]));
        let mut wrong = exported.clone();
        if v.0 == 1 {
            let target = wrong
                .iter_mut()
                .find(|a| {
                    a.tag == ATTRIBUTE
                        && a.get(ATTRIBUTE_NAME).is_some_and(|n| {
                            n.string().ok() == Some("X.509 Certificate Identifier")
                        })
                })
                .unwrap();
            if let keytend_kmip_server::ttlv::Value::Structure(fields) = &mut target.value {
                let value = fields
                    .iter_mut()
                    .find(|a| a.tag == ATTRIBUTE_VALUE)
                    .unwrap();
                if let keytend_kmip_server::ttlv::Value::Structure(values) = &mut value.value {
                    values
                        .iter_mut()
                        .find(|a| a.tag == CERTIFICATE_SERIAL_NUMBER)
                        .unwrap()
                        .value = keytend_kmip_server::ttlv::Value::ByteString(vec![2, 1, 1]);
                }
            }
        } else {
            let target = wrong.iter_mut().find(|a| a.tag == ATTRIBUTES).unwrap();
            if let keytend_kmip_server::ttlv::Value::Structure(fields) = &mut target.value {
                let value = fields
                    .iter_mut()
                    .find(|a| a.tag == X_509_CERTIFICATE_IDENTIFIER)
                    .unwrap();
                if let keytend_kmip_server::ttlv::Value::Structure(values) = &mut value.value {
                    values
                        .iter_mut()
                        .find(|a| a.tag == CERTIFICATE_SERIAL_NUMBER)
                        .unwrap()
                        .value = keytend_kmip_server::ttlv::Value::ByteString(vec![2, 1, 1]);
                }
            }
        }
        wrong.push(Node::boolean(REPLACE_EXISTING, true));
        assert_eq!(reason(&call(&mut f, v, 42, wrong)), 7);
        assert_eq!(f.e.store.get("owner", &id).unwrap().unwrap().state, 5);
        exported.push(Node::boolean(REPLACE_EXISTING, true));
        body(&call(&mut f, v, 42, exported));
        assert!(
            before
                == identity_attrs(&mut f, v, &id)
                    .into_iter()
                    .filter(|a| identity_tag(a.tag))
                    .collect::<Vec<_>>()
        );
        let backup = f._dir.path().join("identity-backup");
        f.e.store.backup(&backup).unwrap();
        let clean = f._dir.path().join("identity-clean");
        std::fs::copy(backup, &clean).unwrap();
        f.e = Engine::new(
            Store::open(&clean, &f._dir.path().join("master")).unwrap(),
            true,
        );
        assert!(
            before
                == identity_attrs(&mut f, v, &id)
                    .into_iter()
                    .filter(|a| identity_tag(a.tag))
                    .collect::<Vec<_>>()
        );
    }
}
#[test]
fn empty_subject_preserves_required_alternative_names() {
    let c = identity_certificate(true);
    let m =
        keytend_kmip_server::crypto::certificate_attributes::inspect(&c.to_der().unwrap()).unwrap();
    assert!(m.subject.is_empty());
    assert!(m.subject_text.is_empty());
    assert_eq!(m.subject_alternatives.len(), 3);
    for v in [Version(1, 1), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new(None);
        let id = register(&mut f, v, &c);
        let a = identity_attrs(&mut f, v, &id);
        let subject = a
            .iter()
            .find(|a| a.tag == X_509_CERTIFICATE_SUBJECT)
            .unwrap();
        assert_eq!(
            subject
                .required(SUBJECT_DISTINGUISHED_NAME)
                .unwrap()
                .byte_string()
                .unwrap(),
            &[] as &[u8]
        );
        assert_eq!(subject.all(SUBJECT_ALTERNATIVE_NAME).count(), 3);
    }
}

#[test]
fn repeated_certificate_identity_declarations_compare_values_without_request_order() {
    let c = identity_certificate(false);
    let v = Version(2, 1);
    let mut f = Fixture::new(None);
    let id = register(&mut f, v, &c);
    let mut declared = identity_attrs(&mut f, v, &id)
        .into_iter()
        .filter(|a| [CERTIFICATE_SUBJECT_CN, CERTIFICATE_ISSUER_OU].contains(&a.tag))
        .collect::<Vec<_>>();
    declared.reverse();
    let mut required = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
        Node::int(CERTIFICATE_LENGTH, c.to_der().unwrap().len() as i32),
    ];
    required.extend(declared.clone());
    body(&call(
        &mut f,
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 1),
            cert(&c),
            attributes(v, required.clone()),
        ],
    ));
    required.pop();
    let before = f.e.store.list("owner").unwrap().len();
    assert_eq!(
        reason(&call(
            &mut f,
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 1),
                cert(&c),
                attributes(v, required)
            ]
        )),
        7
    );
    assert_eq!(f.e.store.list("owner").unwrap().len(), before);
}

#[test]
fn destroyed_certificate_identity_restore_rejects_malformed_encoding_and_missing_alternatives() {
    use keytend_kmip_server::ttlv::Value;
    let c = identity_certificate(false);
    let v = Version(2, 1);
    let mut f = Fixture::new(None);
    let id = register(&mut f, v, &c);
    body(&call(&mut f, v, 20, vec![uid(v, &id)]));
    let exported = body(&call(&mut f, v, 43, vec![uid(v, &id)]))
        .children()
        .unwrap()
        .to_vec();
    for (tag, children) in [
        (
            X_509_CERTIFICATE_SUBJECT,
            vec![Node::bytes(SUBJECT_DISTINGUISHED_NAME, vec![])],
        ),
        (
            X_509_CERTIFICATE_SUBJECT,
            vec![
                Node::bytes(SUBJECT_DISTINGUISHED_NAME, vec![]),
                Node::bytes(SUBJECT_ALTERNATIVE_NAME, vec![0x87, 1, 127]),
            ],
        ),
        (
            X_509_CERTIFICATE_SUBJECT,
            vec![Node::bytes(SUBJECT_DISTINGUISHED_NAME, vec![0x30, 1, 0])],
        ),
        (
            X_509_CERTIFICATE_IDENTIFIER,
            vec![
                Node::bytes(ISSUER_DISTINGUISHED_NAME, c.issuer_name().to_der().unwrap()),
                Node::bytes(CERTIFICATE_SERIAL_NUMBER, vec![]),
            ],
        ),
        (
            X_509_CERTIFICATE_IDENTIFIER,
            vec![
                Node::bytes(ISSUER_DISTINGUISHED_NAME, c.issuer_name().to_der().unwrap()),
                Node::bytes(CERTIFICATE_SERIAL_NUMBER, vec![2, 2, 0, 1]),
            ],
        ),
    ] {
        let before = serde_json::to_value(f.e.store.get("owner", &id).unwrap().unwrap()).unwrap();
        let mut fields = exported.clone();
        if let Value::Structure(attrs) = &mut fields
            .iter_mut()
            .find(|a| a.tag == ATTRIBUTES)
            .unwrap()
            .value
        {
            *attrs.iter_mut().find(|a| a.tag == tag).unwrap() = Node::structure(tag, children);
        }
        fields.push(Node::boolean(REPLACE_EXISTING, true));
        assert_eq!(reason(&call(&mut f, v, 42, fields)), 7);
        assert_eq!(
            before,
            serde_json::to_value(f.e.store.get("owner", &id).unwrap().unwrap()).unwrap()
        );
    }
}

fn role_certificate(
    key: &PKey<Private>,
    issuer: Option<&PKey<Private>>,
    usage: Option<u16>,
) -> X509 {
    use openssl::asn1::{Asn1Object, Asn1OctetString};
    use openssl::x509::X509Extension;
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "signature subject")
        .unwrap();
    let name = name.build();
    let mut issuer_name = X509NameBuilder::new().unwrap();
    issuer_name
        .append_entry_by_text("CN", "different issuer")
        .unwrap();
    let issuer_name = issuer_name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(17).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(if issuer.is_some() {
        &issuer_name
    } else {
        &name
    })
    .unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(now() - 10).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(now() + 1000).unwrap())
        .unwrap();
    if let Some(bits) = usage {
        let count = 16 - bits.leading_zeros() as usize;
        let unused = (8 - count % 8) % 8;
        let mut encoded = vec![3, (count.div_ceil(8) + 1) as u8, unused as u8];
        let mut data = vec![0u8; count.div_ceil(8)];
        for bit in 0..count {
            if bits & (1 << bit) != 0 {
                data[bit / 8] |= 128 >> (bit % 8);
            }
        }
        encoded.extend(data);
        b.append_extension(
            X509Extension::new_from_der(
                &Asn1Object::from_str("2.5.29.15").unwrap(),
                true,
                &Asn1OctetString::new_from_bytes(&encoded).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    }
    b.sign(
        issuer.unwrap_or(key),
        if issuer.is_some() {
            MessageDigest::sha384()
        } else {
            MessageDigest::sha256()
        },
    )
    .unwrap();
    b.build()
}
fn role_register(f: &mut Fixture, v: Version, c: &X509, algorithm: u32, usage: u32) -> String {
    let response = role_register_response(f, v, c, algorithm, usage);
    let id = body(&response)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    body(&call(f, v, 18, vec![uid(v, &id)]));
    id
}
fn role_register_response(
    f: &mut Fixture,
    v: Version,
    c: &X509,
    algorithm: u32,
    usage: u32,
) -> Node {
    call(
        f,
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 1),
            cert(c),
            attributes(
                v,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                    Node::int(CRYPTOGRAPHIC_LENGTH, c.public_key().unwrap().bits() as i32),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage as i32),
                    Node::int(CERTIFICATE_LENGTH, c.to_der().unwrap().len() as i32),
                ],
            ),
        ],
    )
}
fn role_key(rsa: bool) -> PKey<Private> {
    if rsa {
        PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap()
    } else {
        PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap()
    }
}
fn role_signature(key: &PKey<Private>, message: &[u8], pss: bool, legacy: bool) -> Vec<u8> {
    let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), key).unwrap();
    if pss {
        signer
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .unwrap();
        signer
            .set_rsa_mgf1_md(if legacy {
                MessageDigest::sha1()
            } else {
                MessageDigest::sha256()
            })
            .unwrap();
        signer
            .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::custom(if legacy {
                20
            } else {
                32
            }))
            .unwrap();
    }
    signer.update(message).unwrap();
    signer.sign_to_vec().unwrap()
}
fn role_parameters(rsa: bool, pss: bool, v: Version) -> Node {
    let mut fields = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, if rsa { 4 } else { 6 }),
        Node::enumeration(HASHING_ALGORITHM, 6),
    ];
    if rsa {
        fields.push(Node::enumeration(PADDING_METHOD, if pss { 10 } else { 8 }));
        if pss && v >= Version(1, 4) {
            fields.extend([
                Node::enumeration(MASK_GENERATOR_HASHING_ALGORITHM, 6),
                Node::int(SALT_LENGTH, 32),
            ]);
        }
    }
    structure(CRYPTOGRAPHIC_PARAMETERS, fields)
}
#[test]
fn certificate_subject_keys_verify_independent_rsa_pss_and_ecdsa_application_signatures() {
    let message = b"application data, distinct from the certificate signature";
    let rsa = role_key(true);
    let ec = role_key(false);
    for (key, issuer, algorithm, pss) in [
        (&rsa, &ec, 4, false),
        (&rsa, &ec, 4, true),
        (&ec, &rsa, 6, false),
    ] {
        let c = role_certificate(key, Some(issuer), Some(1));
        for v in versions().into_iter().filter(|v| *v >= Version(1, 2)) {
            // 1.0-1.2 PSS uses the PKCS#1 defaults; 1.3 uses MGF1 with the
            // message hash and detects the salt (docs/interpretations.md); 1.4+ is explicit.
            let signature = role_signature(key, message, pss, v < Version(1, 3));
            let mut f = Fixture::new(None);
            let id = role_register(&mut f, v, &c, algorithm, 2);
            let before =
                serde_json::to_value(f.e.store.get("owner", &id).unwrap().unwrap()).unwrap();
            let fields = vec![
                uid(v, &id),
                role_parameters(algorithm == 4, pss, v),
                Node::bytes(DATA, message.to_vec()),
                Node::bytes(SIGNATURE_DATA, signature.clone()),
            ];
            let response = call(&mut f, v, 34, fields.clone());
            assert_eq!(validity(&response), 1);
            assert_eq!(
                body(&response)
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap(),
                id
            );
            let mut damaged = fields.clone();
            damaged.iter_mut().find(|n| n.tag == DATA).unwrap().value =
                keytend_kmip_server::ttlv::Value::ByteString(b"wrong data".to_vec());
            assert_eq!(validity(&call(&mut f, v, 34, damaged)), 2);
            if v >= Version(1, 4) {
                let digest = openssl::hash::hash(MessageDigest::sha256(), message).unwrap();
                let mut prehashed = fields;
                prehashed.iter_mut().find(|n| n.tag == DATA).unwrap().tag = DIGESTED_DATA;
                prehashed
                    .iter_mut()
                    .find(|n| n.tag == DIGESTED_DATA)
                    .unwrap()
                    .value = keytend_kmip_server::ttlv::Value::ByteString(digest.to_vec());
                assert_eq!(validity(&call(&mut f, v, 34, prehashed)), 1);
            }
            assert_eq!(
                serde_json::to_value(f.e.store.get("owner", &id).unwrap().unwrap()).unwrap(),
                before,
                "provider adaptation must not rewrite a Certificate into a Public Key or change its extraction facts"
            );
        }
    }
}
#[test]
fn certificate_verification_respects_key_usage_and_declared_ec_purpose() {
    let key = role_key(false);
    let data = b"purpose restricted";
    let signature = role_signature(&key, data, false, false);
    for usage in [None, Some(1), Some(2), Some(4), Some(32), Some(64)] {
        let c = role_certificate(&key, None, usage);
        for v in [Version(1, 2), Version(2, 1), Version(3, 0)] {
            let mut f = Fixture::new(None);
            if v.0 == 1 && usage.is_some_and(|bits| bits & 1 == 0) {
                // 1.x X.509 Key Usage mapping: only digitalSignature maps to
                // Verify, so the declared Verify mask conflicts.
                // REQ:9447ff61353ae1ef
                assert_eq!(reason(&role_register_response(&mut f, v, &c, 6, 2)), 7);
                continue;
            }
            let id = role_register(&mut f, v, &c, 6, 2);
            let response = call(
                &mut f,
                v,
                34,
                vec![
                    uid(v, &id),
                    role_parameters(false, false, v),
                    Node::bytes(DATA, data.to_vec()),
                    Node::bytes(SIGNATURE_DATA, signature.clone()),
                ],
            );
            if usage.is_none_or(|bits| bits & 3 != 0) {
                assert_eq!(validity(&response), 1);
            } else {
                assert_eq!(reason(&response), if v.0 >= 2 { 0x29 } else { 12 });
            }
        }
    }
    for (algorithm, mask) in [(14, 2), (6, 0)] {
        let c = role_certificate(&key, None, Some(1));
        let mut f = Fixture::new(None);
        let v = Version(2, 1);
        let id = role_register(&mut f, v, &c, algorithm, mask);
        let response = call(
            &mut f,
            v,
            34,
            vec![
                uid(v, &id),
                role_parameters(false, false, v),
                Node::bytes(DATA, data.to_vec()),
                Node::bytes(SIGNATURE_DATA, signature.clone()),
            ],
        );
        assert_eq!(reason(&response), if mask == 0 { 0x29 } else { 8 });
    }
}
#[test]
fn multipart_certificate_verification_binds_original_certificate_and_retains_its_identity() {
    for rsa in [true, false] {
        let key = role_key(rsa);
        let c = role_certificate(&key, None, Some(1));
        let message = b"first and final";
        let signature = role_signature(&key, message, false, false);
        for v in [
            Version(1, 3),
            Version(1, 4),
            Version(2, 0),
            Version(2, 1),
            Version(3, 0),
        ] {
            let mut f = Fixture::new(None);
            let id = role_register(&mut f, v, &c, if rsa { 4 } else { 6 }, 2);
            let initial = call(
                &mut f,
                v,
                34,
                vec![
                    uid(v, &id),
                    role_parameters(rsa, false, v),
                    Node::boolean(INIT_INDICATOR, true),
                    Node::bytes(DATA, b"first ".to_vec()),
                ],
            );
            let token = body(&initial)
                .required(CORRELATION_VALUE)
                .unwrap()
                .byte_string()
                .unwrap()
                .to_vec();
            assert!(body(&initial).get(VALIDITY_INDICATOR).is_none());
            let done = call(
                &mut f,
                v,
                34,
                vec![
                    uid(v, &id),
                    Node::bytes(CORRELATION_VALUE, token),
                    Node::boolean(FINAL_INDICATOR, true),
                    Node::bytes(DATA, b"and final".to_vec()),
                    Node::bytes(SIGNATURE_DATA, signature.clone()),
                ],
            );
            assert_eq!(validity(&done), 1);
            assert_eq!(
                body(&done)
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap(),
                id
            );
            let object = f.e.store.get("owner", &id).unwrap().unwrap();
            assert_eq!(object.object_type, 1);
            assert_eq!(object.material, c.to_der().unwrap());
        }
    }
}

#[test]
fn dsa_certificate_subject_verifies_data_digests_and_multipart_without_using_issuer_algorithm() {
    let key = PKey::from_dsa(openssl::dsa::Dsa::generate(2048).unwrap()).unwrap();
    let issuer = role_key(false);
    let c = role_certificate(&key, Some(&issuer), Some(1));
    let data = b"DSA subject with EC issuer";
    let signature = role_signature(&key, data, false, false);
    for v in versions().into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut f = Fixture::new(None);
        let id = role_register(&mut f, v, &c, 5, 2);
        let cp = structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 5),
                Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 11),
            ],
        );
        let response = call(
            &mut f,
            v,
            34,
            vec![
                uid(v, &id),
                cp.clone(),
                Node::bytes(DATA, data.to_vec()),
                Node::bytes(SIGNATURE_DATA, signature.clone()),
            ],
        );
        assert_eq!(validity(&response), 1);
        let invalid = call(
            &mut f,
            v,
            34,
            vec![
                uid(v, &id),
                cp.clone(),
                Node::bytes(DATA, data.to_vec()),
                Node::bytes(SIGNATURE_DATA, vec![0]),
            ],
        );
        assert_eq!(validity(&invalid), 2);
        if v >= Version(1, 3) {
            let first = call(
                &mut f,
                v,
                34,
                vec![
                    uid(v, &id),
                    cp.clone(),
                    Node::boolean(INIT_INDICATOR, true),
                    Node::bytes(DATA, data[..3].to_vec()),
                ],
            );
            let token = body(&first)
                .required(CORRELATION_VALUE)
                .unwrap()
                .byte_string()
                .unwrap()
                .to_vec();
            let last = call(
                &mut f,
                v,
                34,
                vec![
                    uid(v, &id),
                    Node::bytes(CORRELATION_VALUE, token),
                    Node::boolean(FINAL_INDICATOR, true),
                    Node::bytes(DATA, data[3..].to_vec()),
                    Node::bytes(SIGNATURE_DATA, signature.clone()),
                ],
            );
            assert_eq!(validity(&last), 1);
        }
        if v >= Version(1, 4) {
            let digest = openssl::hash::hash(MessageDigest::sha256(), data).unwrap();
            assert_eq!(
                validity(&call(
                    &mut f,
                    v,
                    34,
                    vec![
                        uid(v, &id),
                        cp,
                        Node::bytes(DIGESTED_DATA, digest.to_vec()),
                        Node::bytes(SIGNATURE_DATA, signature.clone())
                    ]
                )),
                1
            );
        }
        assert_eq!(f.e.store.get("owner", &id).unwrap().unwrap().object_type, 1);
    }
}

#[test]
fn certificate_verification_enforces_tenancy_operation_acl_archival_and_destroyed_state() {
    use keytend_kmip_server::authorization::ObjectGrant;
    let key = role_key(false);
    let c = role_certificate(&key, None, Some(1));
    let data = b"authorization boundary";
    let signature = role_signature(&key, data, false, false);
    let v = Version(2, 1);
    let mut f = Fixture::new(None);
    let id = role_register(&mut f, v, &c, 6, 2);
    let fields = vec![
        uid(v, &id),
        role_parameters(false, false, v),
        Node::bytes(DATA, data.to_vec()),
        Node::bytes(SIGNATURE_DATA, signature),
    ];
    let request = message(v, vec![(34, fields.clone())], vec![]);
    let foreign = f.e.process("other", &request).unwrap();
    assert_eq!(reason(&foreign), not_found(v));
    let denied =
        f.e.process_authorized("owner", &request, Some(&[10, 11]))
            .unwrap();
    assert_eq!(reason(&denied), 12);
    let grants = [ObjectGrant {
        owner: "owner".into(),
        user: None,
        device: None,
        identifier: id.clone(),
        operations: vec![10, 11],
    }];
    let read =
        f.e.process_with_grants(
            "other",
            &message(v, vec![(10, vec![uid(v, &id)])], vec![]),
            Some(&[10, 11, 34]),
            &grants,
        )
        .unwrap();
    body(&read);
    let denied =
        f.e.process_with_grants("other", &request, Some(&[10, 11, 34]), &grants)
            .unwrap();
    assert_eq!(
        reason(&denied),
        not_found(v),
        "a Get grant must not delegate server-side cryptographic operations"
    );
    body(&call(&mut f, v, 21, vec![uid(v, &id)]));
    assert_eq!(reason(&call(&mut f, v, 34, fields.clone())), 13);
    body(&call(&mut f, v, 22, vec![uid(v, &id)]));
    assert_eq!(validity(&call(&mut f, v, 34, fields.clone())), 1);
    let mut dated = f.e.store.get("owner", &id).unwrap().unwrap();
    dated
        .attrs
        .push(Node::date(PROCESS_START_DATE, now() + 300));
    f.e.store.put(&dated).unwrap();
    // Outside the date window: Wrong Key Lifecycle State from 2.1.
    assert_eq!(reason(&call(&mut f, v, 34, fields.clone())), 0x43);
    dated.attrs.retain(|a| a.tag != PROCESS_START_DATE);
    f.e.store.put(&dated).unwrap();
    body(&call(
        &mut f,
        v,
        19,
        vec![
            uid(v, &id),
            Node::structure(
                REVOCATION_REASON,
                vec![Node::enumeration(REVOCATION_REASON_CODE, 2)],
            ),
        ],
    ));
    body(&call(&mut f, v, 20, vec![uid(v, &id)]));
    let destroyed = call(&mut f, v, 34, fields);
    assert_eq!(reason(&destroyed), 0x13);
    assert!(
        destroyed
            .required(BATCH_ITEM)
            .unwrap()
            .get(RESPONSE_PAYLOAD)
            .is_none()
    );
}
#[test]
fn certificate_stream_binding_covers_der_and_verification_survives_restart_and_clean_backup() {
    let key = role_key(false);
    let issuer = role_key(true);
    let c = role_certificate(&key, None, Some(1));
    let changed = role_certificate(&key, Some(&issuer), Some(1));
    assert_eq!(
        c.public_key().unwrap().public_key_to_der().unwrap(),
        changed.public_key().unwrap().public_key_to_der().unwrap()
    );
    assert_ne!(c.to_der().unwrap(), changed.to_der().unwrap());
    let data = b"certificate-bound stream";
    let signature = role_signature(&key, data, false, false);
    let v = Version(2, 1);
    let mut f = Fixture::new(None);
    let id = role_register(&mut f, v, &c, 6, 2);
    let first = call(
        &mut f,
        v,
        34,
        vec![
            uid(v, &id),
            role_parameters(false, false, v),
            Node::boolean(INIT_INDICATOR, true),
            Node::bytes(DATA, data[..3].to_vec()),
        ],
    );
    let token = body(&first)
        .required(CORRELATION_VALUE)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec();
    let original = f.e.store.get("owner", &id).unwrap().unwrap();
    let mut altered = original.clone();
    altered.material = changed.to_der().unwrap();
    f.e.store.put(&altered).unwrap();
    let last = call(
        &mut f,
        v,
        34,
        vec![
            uid(v, &id),
            Node::bytes(CORRELATION_VALUE, token),
            Node::boolean(FINAL_INDICATOR, true),
            Node::bytes(DATA, data[3..].to_vec()),
            Node::bytes(SIGNATURE_DATA, signature.clone()),
        ],
    );
    assert_eq!(
        reason(&last),
        0x2e,
        "same subject key must not hide a different certificate from the multipart binding"
    );
    f.e.store.put(&original).unwrap();
    let fields = vec![
        uid(v, &id),
        role_parameters(false, false, v),
        Node::bytes(DATA, data.to_vec()),
        Node::bytes(SIGNATURE_DATA, signature),
    ];
    let master = f._dir.path().join("master");
    let store = f._dir.path().join("store");
    f.e = Engine::new(Store::open(&store, &master).unwrap(), true);
    assert_eq!(validity(&call(&mut f, v, 34, fields.clone())), 1);
    let backup = f._dir.path().join("role-backup");
    f.e.store.backup(&backup).unwrap();
    let clean = f._dir.path().join("role-clean");
    std::fs::copy(backup, &clean).unwrap();
    f.e = Engine::new(Store::open(&clean, &master).unwrap(), true);
    assert_eq!(validity(&call(&mut f, v, 34, fields)), 1);
    let stored = f.e.store.get("owner", &id).unwrap().unwrap();
    assert_eq!(stored.object_type, 1);
    assert_eq!(stored.material, c.to_der().unwrap());
    assert_eq!(stored.metadata.fresh, Some(true));
}
#[test]
fn certificate_key_usage_framing_is_checked_and_certificate_never_becomes_a_signing_key() {
    let key = role_key(false);
    let v = Version(2, 1);
    let mut f = Fixture::new(None);
    for bits in [0, 1 << 9] {
        let c = role_certificate(&key, None, Some(bits));
        let before = f.e.store.list("owner").unwrap().len();
        assert_eq!(
            reason(&call(
                &mut f,
                v,
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 1),
                    cert(&c),
                    attributes(
                        v,
                        vec![
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2),
                            Node::int(CERTIFICATE_LENGTH, c.to_der().unwrap().len() as i32)
                        ]
                    )
                ]
            )),
            7
        );
        assert_eq!(f.e.store.list("owner").unwrap().len(), before);
    }
    let c = role_certificate(&key, None, Some(1));
    let id = role_register(&mut f, v, &c, 6, 1);
    let response = call(
        &mut f,
        v,
        33,
        vec![
            uid(v, &id),
            role_parameters(false, false, v),
            Node::bytes(DATA, vec![1]),
        ],
    );
    assert_eq!(reason(&response), 8);
    let v = Version(1, 1);
    let id = role_register(&mut f, v, &c, 6, 2);
    let unavailable = call(
        &mut f,
        v,
        34,
        vec![
            uid(v, &id),
            role_parameters(false, false, v),
            Node::bytes(DATA, vec![1]),
            Node::bytes(SIGNATURE_DATA, vec![1]),
        ],
    );
    assert_eq!(reason(&unavailable), 5);
}

#[test]
fn unrestricted_certificate_usage_does_not_override_public_key_or_certificate_purpose() {
    let key = role_key(false);
    let data = b"unrestricted is not a private-key or X.509 purpose override";
    let signature = role_signature(&key, data, false, false);
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        for (key_usage, algorithm, denied) in [(1, 6, None), (4, 6, Some(0x29)), (1, 14, Some(8))] {
            let c = role_certificate(&key, None, Some(key_usage));
            let mut f = Fixture::new(None);
            let id = role_register(&mut f, v, &c, algorithm, 0x20_0000);
            let response = call(
                &mut f,
                v,
                34,
                vec![
                    uid(v, &id),
                    role_parameters(false, false, v),
                    Node::bytes(DATA, data.to_vec()),
                    Node::bytes(SIGNATURE_DATA, signature.clone()),
                ],
            );
            if let Some(expected) = denied {
                assert_eq!(reason(&response), expected);
            } else {
                assert_eq!(validity(&response), 1);
            }
            let sign = call(
                &mut f,
                v,
                33,
                vec![
                    uid(v, &id),
                    role_parameters(false, false, v),
                    Node::bytes(DATA, data.to_vec()),
                ],
            );
            assert_eq!(
                reason(&sign),
                8,
                "Unrestricted must never turn a public certificate into a private signing key"
            );
        }
    }
}
