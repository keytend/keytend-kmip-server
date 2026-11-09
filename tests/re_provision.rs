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

//! Re-Provision (2.0 section 6.1.44, 2.1 section 6.1.48, draft 3.0):
//! the three request forms, the same-message retrieval rule, refusals that
//! would lock a client out, and retirement at the commit of the message.
//! Synthetic `Channel`s stand in for the TLS connection; the issued
//! certificates are checked with an independent OpenSSL path validation.
use keytend_kmip_server::{
    credentials::{PasswordVerifier, PolicyUser},
    protocol::{
        Channel, Engine, Lookup, Outbound, Provisioning, ServerToClient, Subscription, Version,
    },
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
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

const V20: Version = Version(2, 0);
const V21: Version = Version(2, 1);
const V3: Version = Version(3, 0);
const OWNER: &str = "alice";
/// Object Not Found (2.0 and later).
const NOT_FOUND: u32 = 0x37;
/// Re-Provision, Get, Get Attributes and a few unrelated operations.
const OPS: &[u32] = &[1, 2, 3, 8, 10, 11, 18, 20, 24, 45, 53];

type Verify = Box<dyn Fn(&X509, &[X509]) -> Result<(), String> + Send + Sync>;

fn rsa(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
}
fn ec(nid: Nid) -> PKey<Private> {
    PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(nid).unwrap()).unwrap()).unwrap()
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
fn ca_certificate(key: &PKey<Private>, cn: &str) -> X509 {
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&serial()).unwrap();
    b.set_subject_name(&name(cn)).unwrap();
    b.set_issuer_name(&name(cn)).unwrap();
    b.set_pubkey(key).unwrap();
    // Valid since yesterday, like a CA in use.
    b.set_not_before(&Asn1Time::from_unix(keytend_kmip_server::store::now() - 86_400).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
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
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build()
}
struct Leaf<'a> {
    cn: &'a str,
    dns: &'a str,
    client_auth: bool,
    ca: bool,
}
const CLIENT: Leaf = Leaf {
    cn: "client",
    dns: "client.example",
    client_auth: true,
    ca: false,
};
fn leaf(issuer: &X509, issuer_key: &PKey<Private>, key: &PKey<Private>, l: &Leaf) -> X509 {
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&serial()).unwrap();
    b.set_subject_name(&name(l.cn)).unwrap();
    b.set_issuer_name(issuer.subject_name()).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(10).unwrap())
        .unwrap();
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    if l.ca {
        constraints.ca();
    }
    b.append_extension(constraints.build().unwrap()).unwrap();
    b.append_extension(KeyUsage::new().digital_signature().build().unwrap())
        .unwrap();
    if l.client_auth {
        b.append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
            .unwrap();
    } else {
        b.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
    }
    let san = SubjectAlternativeName::new()
        .dns(l.dns)
        .build(&b.x509v3_context(Some(issuer), None))
        .unwrap();
    b.append_extension(san).unwrap();
    b.sign(issuer_key, MessageDigest::sha256()).unwrap();
    b.build()
}
fn csr(key: &PKey<Private>, cn: &str, dns: &str, digest: MessageDigest) -> X509Req {
    let mut b = X509ReqBuilder::new().unwrap();
    b.set_subject_name(&name(cn)).unwrap();
    b.set_pubkey(key).unwrap();
    let mut extensions = Stack::new().unwrap();
    extensions
        .push(
            SubjectAlternativeName::new()
                .dns(dns)
                .build(&b.x509v3_context(None))
                .unwrap(),
        )
        .unwrap();
    b.add_extensions(&extensions).unwrap();
    b.sign(key, digest).unwrap();
    b.build()
}
fn fingerprint(cert: &X509) -> String {
    hex::encode(cert.digest(MessageDigest::sha256()).unwrap())
}
fn sans(cert: &X509) -> Vec<String> {
    cert.subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|n| n.dnsname().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
/// An OpenSSL client-purpose path validation against `trusted`, as the
/// listener does.
fn verifier(trusted: Vec<X509>) -> Verify {
    let mut b = X509StoreBuilder::new().unwrap();
    for cert in trusted {
        b.add_cert(cert).unwrap();
    }
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

struct Fx {
    dir: tempfile::TempDir,
    e: Engine,
    ca: X509,
    ca_key: PKey<Private>,
    f: X509,
    f_key: PKey<Private>,
    channel: Channel,
    ops: Vec<u32>,
}
fn write_private(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn store(dir: &std::path::Path) -> Store {
    let master = dir.join("master");
    if !master.exists() {
        write_private(&master, &[3; 32]);
    }
    Store::open(&dir.join("store.sqlite"), &master).unwrap()
}
impl Fx {
    fn new() -> Self {
        Self::with(rsa(2048), rsa(2048), |ca| verifier(vec![ca.clone()]))
    }
    fn with(
        ca_key: PKey<Private>,
        f_key: PKey<Private>,
        verify: impl FnOnce(&X509) -> Verify,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = ca_certificate(&ca_key, "provisioning CA");
        let f = leaf(&ca, &ca_key, &f_key, &CLIENT);
        let channel = Channel {
            fingerprint: fingerprint(&f),
            policy_fingerprint: fingerprint(&f),
            certificate: f.to_der().unwrap(),
            chain: vec![],
        };
        let e = Engine::new(store(dir.path()), true);
        let mut fx = Self {
            dir,
            e,
            ca,
            ca_key,
            f,
            f_key,
            channel,
            ops: OPS.to_vec(),
        };
        let provisioning = fx.provisioning(verify(&fx.ca.clone()));
        fx.e = std::mem::replace(&mut fx.e, Engine::new(store(fx.dir.path()), true))
            .with_provisioning(provisioning);
        fx
    }
    fn provisioning(&self, verify: Verify) -> Provisioning {
        let ca = self.dir.path().join("ca.pem");
        let key = self.dir.path().join("ca.key");
        std::fs::write(&ca, self.ca.to_pem().unwrap()).unwrap();
        write_private(&key, &self.ca_key.private_key_to_pem_pkcs8().unwrap());
        Provisioning::load(
            &ca,
            &key,
            verify,
            HashSet::from([self.channel.fingerprint.clone()]),
        )
        .unwrap()
    }
    /// A Re-Provision-capable engine reopened on the same store.
    fn reopen(&mut self, provisioning: bool) {
        let e = Engine::new(store(self.dir.path()), true);
        self.e = if provisioning {
            let p = self.provisioning(verifier(vec![self.ca.clone()]));
            e.with_provisioning(p)
        } else {
            e
        };
    }
    fn send_on(&mut self, channel: &Channel, msg: &Node) -> Node {
        let ops = self.ops.clone();
        self.e
            .with_channel(channel, |e| {
                e.process_with_grants(OWNER, msg, Some(&ops), &[])
            })
            .unwrap()
    }
    fn send(&mut self, msg: &Node) -> Node {
        let channel = self.channel.clone();
        self.send_on(&channel, msg)
    }
    fn lookup(&self, cert: &X509) -> Lookup {
        self.e.provisioned_lookup(&fingerprint(cert)).unwrap()
    }
    fn channel_for(&self, cert: &X509) -> Channel {
        Channel {
            fingerprint: fingerprint(cert),
            policy_fingerprint: self.channel.policy_fingerprint.clone(),
            certificate: cert.to_der().unwrap(),
            chain: vec![],
        }
    }
    fn issue(&self, key: &PKey<Private>, l: &Leaf) -> X509 {
        leaf(&self.ca, &self.ca_key, key, l)
    }
}

fn request(v: Version, header: Vec<Node>, items: Vec<(u32, Vec<Node>)>) -> Node {
    let mut h = vec![v.node()];
    if v.0 < 3 {
        h.push(Node::int(BATCH_COUNT, items.len() as i32));
    }
    h.extend(header);
    let mut fields = vec![Node::structure(REQUEST_HEADER, h)];
    let many = items.len() > 1;
    for (i, (op, p)) in items.into_iter().enumerate() {
        let mut item = vec![
            Node::enumeration(OPERATION, op),
            Node::structure(REQUEST_PAYLOAD, p),
        ];
        if many && v.0 < 3 {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8]));
        }
        fields.push(Node::structure(BATCH_ITEM, item));
    }
    Node::structure(REQUEST_MESSAGE, fields)
}
fn items(r: &Node) -> Vec<&Node> {
    r.all(BATCH_ITEM).collect()
}
fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
fn reason_of(item: &Node) -> u32 {
    assert_eq!(status(item), 1, "{}", serde_json::to_string(item).unwrap());
    item.required(RESULT_REASON).unwrap().number().unwrap()
}
fn reason(r: &Node) -> u32 {
    reason_of(items(r)[0])
}
fn payload(item: &Node) -> &Node {
    assert_eq!(status(item), 0, "{}", serde_json::to_string(item).unwrap());
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn uid_of(item: &Node) -> String {
    payload(item)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
/// The ID Placeholder: omitted in 2.x, the enumeration in draft 3.0.
fn placeholder(v: Version) -> Vec<Node> {
    if v.0 >= 3 {
        vec![Node::enumeration(UNIQUE_IDENTIFIER, 1)]
    } else {
        vec![]
    }
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn csr_field(request: &X509Req) -> Node {
    Node::structure(
        CERTIFICATE_REQUEST,
        vec![
            Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
            Node::bytes(CERTIFICATE_REQUEST_VALUE, request.to_der().unwrap()),
        ],
    )
}
fn certificate_field(cert: &X509) -> Node {
    Node::structure(
        CERTIFICATE,
        vec![
            Node::enumeration(CERTIFICATE_TYPE, 1),
            Node::bytes(CERTIFICATE_VALUE, cert.to_der().unwrap()),
        ],
    )
}
fn certificate_in(get: &Node) -> X509 {
    let value = payload(get)
        .required(CERTIFICATE)
        .unwrap()
        .required(CERTIFICATE_VALUE)
        .unwrap()
        .byte_string()
        .unwrap();
    X509::from_der(value).unwrap()
}
fn key_material(get: &Node) -> Vec<u8> {
    payload(get)
        .required(PRIVATE_KEY)
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
fn get(v: Version, id: &str) -> (u32, Vec<Node>) {
    (10, vec![uid(v, id)])
}
fn located(fx: &mut Fx, v: Version) -> usize {
    let r = fx.send(&request(v, vec![], vec![(8, vec![])]));
    payload(items(&r)[0]).all(UNIQUE_IDENTIFIER).count()
}
/// The CSR form: [Re-Provision(CSR), Get(placeholder)].
fn csr_message(v: Version, request_: &X509Req) -> Node {
    request(
        v,
        vec![],
        vec![(53, vec![csr_field(request_)]), (10, placeholder(v))],
    )
}
/// Get Attributes of the placeholder, for its PKCS#12 Certificate Link.
fn link_attributes(v: Version) -> (u32, Vec<Node>) {
    let mut p = placeholder(v);
    p.push(Node::enumeration(
        ATTRIBUTE_REFERENCE,
        if v.0 >= 3 {
            PKCS_12_CERTIFICATE_LINK
        } else {
            LINK
        },
    ));
    (11, p)
}
/// The no-parameter form: [Re-Provision, Get(ph), Get Attributes(ph, Link)].
fn generated_message(v: Version) -> Node {
    generated_with(v, vec![])
}
fn generated_with(v: Version, header: Vec<Node>) -> Node {
    request(
        v,
        header,
        vec![(53, vec![]), (10, placeholder(v)), link_attributes(v)],
    )
}
/// The PKCS#12 Certificate Link of a private key's Get Attributes answer.
fn certificate_link(v: Version, attributes: &Node) -> String {
    let attrs = payload(attributes).required(ATTRIBUTES).unwrap();
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
        .expect("PKCS#12 Certificate Link")
        .required(LINKED_OBJECT_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn query_operations(fx: &mut Fx, v: Version) -> Vec<u32> {
    let r = fx.send(&request(
        v,
        vec![],
        vec![(24, vec![Node::enumeration(QUERY_FUNCTION, 1)])],
    ));
    payload(items(&r)[0])
        .all(OPERATION)
        .map(|n| n.number().unwrap())
        .collect()
}
/// Independent check: the certificate chains to the CA for client use.
fn chains(fx: &Fx, cert: &X509) {
    verifier(vec![fx.ca.clone()])(cert, &[]).unwrap();
}
fn assert_unchanged(fx: &Fx) {
    assert_eq!(fx.lookup(&fx.f), Lookup::Unknown);
}

#[test]
fn offered_only_with_a_provisioning_ca_and_only_from_2_0() {
    let mut fx = Fx::new();
    for v in [Version(1, 4), V20, V21, V3] {
        assert_eq!(
            query_operations(&mut fx, v).contains(&53),
            v.0 >= 2,
            "{v:?}"
        );
    }
    fx.reopen(false);
    for v in [V20, V21, V3] {
        assert!(!query_operations(&mut fx, v).contains(&53));
        let r = fx.send(&generated_message(v));
        assert_eq!(reason(&r), 5);
    }
}

#[test]
fn csr_form_reissues_the_current_identity_and_retires_it_at_commit() {
    for v in [V20, V21, V3] {
        let mut fx = Fx::new();
        let key = rsa(2048);
        // The CSR asks for another identity; the server ignores it.
        let r = fx.send(&csr_message(
            v,
            &csr(&key, "intruder", "evil.example", MessageDigest::sha256()),
        ));
        let [reprovision, delivered] = items(&r)[..] else {
            panic!("two items")
        };
        let id = uid_of(reprovision);
        assert_eq!(uid_of(delivered), id);
        let n = certificate_in(delivered);
        assert_eq!(
            n.subject_name().to_der().unwrap(),
            fx.f.subject_name().to_der().unwrap()
        );
        assert_eq!(sans(&n), vec!["client.example".to_owned()]);
        assert!(n.public_key().unwrap().public_eq(&key));
        chains(&fx, &n);
        let text = String::from_utf8(n.to_text().unwrap()).unwrap();
        assert!(text.contains("TLS Web Client Authentication"), "{text}");
        assert!(text.contains("CA:FALSE"), "{text}");
        assert!(
            text.contains("Digital Signature, Key Encipherment"),
            "{text}"
        );
        // Retired at the commit; the new certificate maps to the anchor.
        assert_eq!(fx.lookup(&fx.f), Lookup::Retired);
        assert_eq!(
            fx.lookup(&n),
            Lookup::Replacement {
                policy_fingerprint: fx.channel.fingerprint.clone(),
                principal: OWNER.into()
            }
        );
        // The open connection continues but cannot re-provision again.
        assert_eq!(located(&mut fx, v), 1);
        let again = fx.send(&csr_message(
            v,
            &csr(&rsa(2048), "client", "x", MessageDigest::sha256()),
        ));
        assert_eq!(reason(&again), 12);
        // The new certificate's connection can.
        let channel = fx.channel_for(&n);
        let r = fx.send_on(
            &channel,
            &csr_message(v, &csr(&rsa(2048), "c", "d", MessageDigest::sha256())),
        );
        let second = certificate_in(items(&r)[1]);
        assert_eq!(fx.lookup(&n), Lookup::Retired);
        assert_eq!(
            fx.lookup(&second),
            Lookup::Replacement {
                policy_fingerprint: fx.channel.fingerprint.clone(),
                principal: OWNER.into()
            }
        );
        // Provisioned certificates are linked as replacement and replaced.
        let attributes = fx.send_on(&channel, &request(v, vec![], vec![(11, vec![uid(v, &id)])]));
        let attrs = payload(items(&attributes)[0]).required(ATTRIBUTES).unwrap();
        let replacement = if v.0 >= 3 {
            attrs
                .get(REPLACEMENT_OBJECT_LINK)
                .map(|n| n.identifier_text().unwrap().to_owned())
        } else {
            attrs
                .all(LINK)
                .find(|l| l.get(LINK_TYPE).unwrap().number().unwrap() == 0x106)
                .map(|l| {
                    l.required(LINKED_OBJECT_IDENTIFIER)
                        .unwrap()
                        .identifier_text()
                        .unwrap()
                        .to_owned()
                })
        };
        assert_eq!(replacement, Some(uid_of(items(&r)[0])), "{v:?}");
    }
}

#[test]
fn no_parameter_form_delivers_a_message_scoped_private_key() {
    for (v, f_key) in [
        (V21, rsa(2048)),
        (V20, ec(Nid::X9_62_PRIME256V1)),
        (V3, ec(Nid::SECP384R1)),
    ] {
        let ca_key = rsa(2048);
        let mut fx = Fx::with(ca_key, f_key, |ca| verifier(vec![ca.clone()]));
        let r = fx.send(&generated_message(v));
        let [reprovision, key, attributes] = items(&r)[..] else {
            panic!("three items")
        };
        let key_id = uid_of(reprovision);
        assert_eq!(uid_of(key), key_id);
        payload(key).required(PRIVATE_KEY).unwrap();
        let cert_id = certificate_link(v, attributes);
        assert_eq!(fx.lookup(&fx.f), Lookup::Retired);
        // The key is gone after the message, for this connection too.
        let r = fx.send(&request(v, vec![], vec![get(v, &key_id)]));
        assert_eq!(reason(&r), NOT_FOUND, "{v:?}");
        // The certificate stays and is fetched on the same open connection.
        let r = fx.send(&request(v, vec![], vec![get(v, &cert_id)]));
        let n = certificate_in(items(&r)[0]);
        chains(&fx, &n);
        assert_eq!(
            n.subject_name().to_der().unwrap(),
            fx.f.subject_name().to_der().unwrap()
        );
        let public = n.public_key().unwrap();
        let f_public = fx.f.public_key().unwrap();
        assert_eq!(public.id(), f_public.id());
        assert!(!public.public_eq(&f_public));
        if public.id() == Id::RSA {
            assert_eq!(public.bits(), f_public.bits());
            let material = key_material(key);
            let private = openssl::rsa::Rsa::private_key_from_der(&material)
                .map(|r| PKey::from_rsa(r).unwrap())
                .unwrap();
            assert!(private.public_eq(&public));
        } else {
            assert_eq!(
                public.ec_key().unwrap().group().curve_name(),
                f_public.ec_key().unwrap().group().curve_name()
            );
        }
        assert_eq!(
            fx.lookup(&n),
            Lookup::Replacement {
                policy_fingerprint: fx.channel.fingerprint.clone(),
                principal: OWNER.into()
            }
        );
        // Another certificate of the same principal never sees the key.
        let other = fx.issue(&rsa(2048), &CLIENT);
        let mut restricted = fx.channel_for(&other);
        restricted.policy_fingerprint = fingerprint(&other);
        fx.ops = vec![8, 10, 11];
        let r = fx.send_on(&restricted, &request(v, vec![], vec![get(v, &key_id)]));
        assert_eq!(reason(&r), NOT_FOUND);
        let r = fx.send_on(&restricted, &request(v, vec![], vec![(8, vec![])]));
        let ids: Vec<_> = payload(items(&r)[0])
            .all(UNIQUE_IDENTIFIER)
            .map(|n| n.identifier_text().unwrap().to_owned())
            .collect();
        assert_eq!(ids, vec![cert_id.clone()]);
    }
}

#[test]
fn certificate_form_adopts_a_certificate_of_the_same_identity() {
    let mut fx = Fx::new();
    let adopted = fx.issue(&rsa(2048), &CLIENT);
    let r = fx.send(&request(
        V21,
        vec![],
        vec![(53, vec![certificate_field(&adopted)])],
    ));
    let id = uid_of(items(&r)[0]);
    assert_eq!(fx.lookup(&fx.f), Lookup::Retired);
    assert_ne!(fx.lookup(&adopted), Lookup::Unknown);
    let r = fx.send(&request(V21, vec![], vec![get(V21, &id)]));
    assert_eq!(
        certificate_in(items(&r)[0]).to_der().unwrap(),
        adopted.to_der().unwrap()
    );
}

#[test]
fn adopted_certificates_must_be_new_client_certificates_of_the_same_identity() {
    let mut fx = Fx::new();
    let ec_key = ec(Nid::X9_62_PRIME256V1);
    let other_ca_key = rsa(2048);
    let other_ca = ca_certificate(&other_ca_key, "other");
    let cases = [
        // Another subject or SAN.
        fx.issue(
            &rsa(2048),
            &Leaf {
                cn: "someone",
                ..CLIENT
            },
        ),
        fx.issue(
            &rsa(2048),
            &Leaf {
                dns: "other.example",
                ..CLIENT
            },
        ),
        // No clientAuth EKU, or a CA certificate.
        fx.issue(
            &rsa(2048),
            &Leaf {
                client_auth: false,
                ..CLIENT
            },
        ),
        fx.issue(&rsa(2048), &Leaf { ca: true, ..CLIENT }),
        // The current certificate itself, and one re-issued for its key.
        fx.f.clone(),
        fx.issue(&fx.f_key.clone(), &CLIENT),
        // Another key algorithm.
        fx.issue(&ec_key, &CLIENT),
        // Not trusted by the listener.
        leaf(&other_ca, &other_ca_key, &rsa(2048), &CLIENT),
    ];
    for cert in &cases {
        let r = fx.send(&request(
            V21,
            vec![],
            vec![(53, vec![certificate_field(cert)])],
        ));
        assert_eq!(reason(&r), 7, "{}", cert.subject_name().entries().count());
        assert_unchanged(&fx);
    }
    // A certificate that is already a credential in the policy.
    let listed = fx.issue(&rsa(2048), &CLIENT);
    let ca_path = fx.dir.path().join("ca.pem");
    let key_path = fx.dir.path().join("ca.key");
    let p = Provisioning::load(
        &ca_path,
        &key_path,
        verifier(vec![fx.ca.clone()]),
        HashSet::from([fx.channel.fingerprint.clone(), fingerprint(&listed)]),
    )
    .unwrap();
    fx.e = Engine::new(store(fx.dir.path()), true).with_provisioning(p);
    let r = fx.send(&request(
        V21,
        vec![],
        vec![(53, vec![certificate_field(&listed)])],
    ));
    assert_eq!(reason(&r), 7);
    // Only X.509 certificates.
    let pgp = Node::structure(
        CERTIFICATE,
        vec![
            Node::enumeration(CERTIFICATE_TYPE, 2),
            Node::bytes(CERTIFICATE_VALUE, vec![0x99, 0, 1]),
        ],
    );
    assert_eq!(
        reason(&fx.send(&request(V21, vec![], vec![(53, vec![pgp])]))),
        8
    );
    assert_unchanged(&fx);
}

#[test]
fn certificate_requests_must_carry_a_new_key_of_the_same_kind() {
    let mut fx = Fx::new();
    let f_key = fx.f_key.clone();
    let cases: Vec<(Node, u32)> = vec![
        // The current key.
        (
            csr_field(&csr(&f_key, "client", "c", MessageDigest::sha256())),
            7,
        ),
        // A SHA-1 self-signature.
        (
            csr_field(&csr(&rsa(2048), "client", "c", MessageDigest::sha1())),
            7,
        ),
        // An EC key for an RSA certificate.
        (
            csr_field(&csr(
                &ec(Nid::X9_62_PRIME256V1),
                "client",
                "c",
                MessageDigest::sha256(),
            )),
            7,
        ),
        // CRMF is not implemented, PGP is reserved, garbage is invalid.
        (
            Node::structure(
                CERTIFICATE_REQUEST,
                vec![
                    Node::enumeration(CERTIFICATE_REQUEST_TYPE, 1),
                    Node::bytes(CERTIFICATE_REQUEST_VALUE, vec![0x30, 0]),
                ],
            ),
            8,
        ),
        (
            Node::structure(
                CERTIFICATE_REQUEST,
                vec![
                    Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                    Node::bytes(CERTIFICATE_REQUEST_VALUE, vec![0x30, 0]),
                ],
            ),
            7,
        ),
    ];
    for (field, expected) in cases {
        let r = fx.send(&request(V21, vec![], vec![(53, vec![field]), (10, vec![])]));
        assert_eq!(reason(&r), expected);
        assert_unchanged(&fx);
    }
    // Both a request and a certificate.
    let both = vec![
        csr_field(&csr(&rsa(2048), "client", "c", MessageDigest::sha256())),
        certificate_field(&fx.issue(&rsa(2048), &CLIENT)),
    ];
    let r = fx.send(&request(V21, vec![], vec![(53, both), (10, vec![])]));
    assert_eq!(reason(&r), 7);
    assert_unchanged(&fx);
    // A key the principal used before: F's key from N's connection.
    let r = fx.send(&csr_message(
        V21,
        &csr(&rsa(2048), "client", "c", MessageDigest::sha256()),
    ));
    let n = certificate_in(items(&r)[1]);
    let channel = fx.channel_for(&n);
    let r = fx.send_on(
        &channel,
        &csr_message(V21, &csr(&f_key, "client", "c", MessageDigest::sha256())),
    );
    assert_eq!(reason(&r), 7);
    assert_ne!(fx.lookup(&n), Lookup::Retired);
}

#[test]
fn a_re_provision_that_could_not_be_delivered_is_refused_before_issuing() {
    let mut fx = Fx::new();
    let request_ = csr(&rsa(2048), "client", "c", MessageDigest::sha256());
    for msg in [
        // Re-Provision alone.
        request(V21, vec![], vec![(53, vec![])]),
        request(V21, vec![], vec![(53, vec![csr_field(&request_)])]),
        // Without the Get Attributes that names the certificate.
        request(V21, vec![], vec![(53, vec![]), (10, vec![])]),
        // A Get of another object does not deliver.
        request(V21, vec![], vec![(53, vec![]), get(V21, "x"), (11, vec![])]),
        // Draft 3.0 needs the ID Placeholder enumeration.
        request(V3, vec![], vec![(53, vec![]), (10, vec![]), (11, vec![])]),
    ] {
        let r = fx.send(&msg);
        assert_eq!(reason_of(items(&r)[0]), 7);
        assert_unchanged(&fx);
    }
    assert_eq!(located(&mut fx, V21), 0);
}

#[test]
fn a_failed_delivering_get_fails_the_whole_message() {
    let mut fx = Fx::with(rsa(2048), ec(Nid::X9_62_PRIME256V1), |ca| {
        verifier(vec![ca.clone()])
    });
    // Grow the Maximum Response Size until the message succeeds. Before
    // that, some size admits the Re-Provision answer but not the key: the
    // Get fails, the commit guard fails the message, and nothing commits.
    let mut guarded = false;
    for size in (300..3000).step_by(8) {
        let header = vec![
            Node::int(MAXIMUM_RESPONSE_SIZE, size),
            Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 2),
        ];
        let r = fx.send(&generated_with(V21, header));
        let all = items(&r);
        if all.len() == 1 && status(all[0]) == 1 {
            assert_unchanged(&fx);
            if reason_of(all[0]) == 7 && !guarded {
                guarded = true;
                assert_eq!(located(&mut fx, V21), 0);
                // The next, unrelated request works.
                let r = fx.send(&request(
                    V21,
                    vec![],
                    vec![(
                        1,
                        vec![
                            Node::enumeration(OBJECT_TYPE, 2),
                            Node::structure(
                                ATTRIBUTES,
                                vec![
                                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                                    Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                                ],
                            ),
                        ],
                    )],
                ));
                let key = uid_of(items(&r)[0]);
                let r = fx.send(&request(V21, vec![], vec![get(V21, &key)]));
                payload(items(&r)[0]);
            }
            continue;
        }
        assert!(guarded, "the commit guard never failed a message");
        // The message commits only once every item fits: the key and the
        // certificate's identifier both reached the client.
        let statuses: Vec<_> = all.iter().map(|i| status(i)).collect();
        assert_eq!(statuses, [0, 0, 0]);
        assert_eq!(fx.lookup(&fx.f), Lookup::Retired);
        return;
    }
    panic!("no size admitted the message");
}

#[test]
fn a_rejected_re_provision_response_rolls_back_cleanly_in_a_continue_batch() {
    let mut fx = Fx::with(rsa(2048), ec(Nid::X9_62_PRIME256V1), |ca| {
        verifier(vec![ca.clone()])
    });
    let mut seen = false;
    for size in (200..3000).step_by(8) {
        let header = vec![
            Node::int(MAXIMUM_RESPONSE_SIZE, size),
            Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1),
        ];
        let channel = fx.channel.clone();
        let ops = fx.ops.clone();
        let msg = generated_with(V21, header);
        let Ok(r) = fx.e.with_channel(&channel, |e| {
            e.process_with_grants(OWNER, &msg, Some(&ops), &[])
        }) else {
            // Too small for any answer.
            continue;
        };
        let all = items(&r);
        if all.len() == 3 && status(all[0]) == 1 {
            assert_eq!(reason_of(all[0]), 2);
            seen = true;
            assert_unchanged(&fx);
            assert_eq!(located(&mut fx, V21), 0);
        }
        if all.len() == 3 && status(all[0]) == 0 {
            break;
        }
    }
    assert!(seen, "no size rejected only the Re-Provision response");
}

#[test]
fn tickets_credential_identities_and_missing_channels_are_refused() {
    let mut fx = Fx::new();
    fx.e.add_policy_users(
        OWNER,
        vec![PolicyUser {
            username: "administrator".into(),
            password_scrypt: PasswordVerifier::new(b"password").unwrap(),
            administrator: true,
            hashed_password: None,
            one_time_password: None,
        }],
    )
    .unwrap();
    let password = Node::structure(
        AUTHENTICATION,
        vec![Node::structure(
            CREDENTIAL,
            vec![
                Node::enumeration(CREDENTIAL_TYPE, 1),
                Node::structure(
                    CREDENTIAL_VALUE,
                    vec![
                        Node::text(USERNAME, "administrator"),
                        Node::text(PASSWORD, "password"),
                    ],
                ),
            ],
        )],
    );
    // A draft 3.0 Login ticket on this connection.
    let r = fx.send(&request(V3, vec![password.clone()], vec![(45, vec![])]));
    let ticket = payload(items(&r)[0]).required(TICKET).unwrap().clone();
    let by_ticket = Node::structure(
        AUTHENTICATION,
        vec![Node::structure(
            CREDENTIAL,
            vec![
                Node::enumeration(CREDENTIAL_TYPE, 6),
                Node::structure(CREDENTIAL_VALUE, vec![ticket]),
            ],
        )],
    );
    let r = fx.send(&generated_with(V3, vec![by_ticket]));
    assert_eq!(reason(&r), 12);
    assert_unchanged(&fx);
    // Credential identity in effect: the objects would not be the
    // certificate principal's.
    fx.e.use_credential_identity(OWNER);
    let r = fx.send(&generated_with(V21, vec![password]));
    assert_eq!(reason(&r), 12);
    assert_unchanged(&fx);
    // No TLS channel (in-process callers).
    let ops = fx.ops.clone();
    let r =
        fx.e.process_with_grants(OWNER, &generated_message(V21), Some(&ops), &[])
            .unwrap();
    assert_eq!(reason(&r), 12);
    assert_unchanged(&fx);
}

#[test]
fn the_allowlist_must_permit_the_retrieval() {
    let mut fx = Fx::new();
    fx.ops = vec![10, 53];
    assert_eq!(reason(&fx.send(&generated_message(V21))), 12);
    fx.ops = vec![11, 53];
    let request_ = csr(&rsa(2048), "client", "c", MessageDigest::sha256());
    assert_eq!(reason(&fx.send(&csr_message(V21, &request_))), 12);
    fx.ops = vec![10, 11];
    assert_eq!(reason(&fx.send(&generated_message(V21))), 12);
    assert_unchanged(&fx);
    // The minimum: 53 and 10 for a CSR.
    fx.ops = vec![10, 53];
    let r = fx.send(&csr_message(V21, &request_));
    payload(items(&r)[1]);
}

#[test]
fn undo_batches_and_mandatory_asynchronous_requests_are_refused() {
    let mut fx = Fx::new();
    let undo = generated_with(
        V21,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
    );
    assert_eq!(reason(&fx.send(&undo)), 8);
    let mandatory = generated_with(V21, vec![Node::enumeration(ASYNCHRONOUS_INDICATOR, 1)]);
    assert_eq!(reason(&fx.send(&mandatory)), 7);
    assert_unchanged(&fx);
}

#[test]
fn the_listener_verifier_decides_before_anything_is_written() {
    // An issued leaf the listener would refuse: Cryptographic Failure.
    let mut fx = Fx::with(rsa(2048), rsa(2048), |_| {
        Box::new(|leaf: &X509, _: &[X509]| {
            if leaf.not_after() > Asn1Time::days_from_now(20).unwrap().as_ref() {
                Err("refused".into())
            } else {
                Ok(())
            }
        })
    });
    let request_ = csr(&rsa(2048), "client", "c", MessageDigest::sha256());
    assert_eq!(reason(&fx.send(&csr_message(V21, &request_))), 10);
    assert_eq!(reason(&fx.send(&generated_message(V21))), 10);
    assert_unchanged(&fx);
    assert_eq!(located(&mut fx, V21), 0);
    // A current certificate the listener no longer accepts (expired or
    // revoked): Permission Denied.
    let mut fx = Fx::with(rsa(2048), rsa(2048), |_| {
        Box::new(|_: &X509, _: &[X509]| Err("revoked".into()))
    });
    assert_eq!(reason(&fx.send(&csr_message(V21, &request_))), 12);
    assert_unchanged(&fx);
}

#[test]
fn a_client_sent_intermediate_is_used_to_re_verify_the_current_certificate() {
    let root_key = rsa(2048);
    let root = ca_certificate(&root_key, "root");
    let intermediate_key = rsa(2048);
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&serial()).unwrap();
    b.set_subject_name(&name("intermediate")).unwrap();
    b.set_issuer_name(root.subject_name()).unwrap();
    b.set_pubkey(&intermediate_key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(20).unwrap())
        .unwrap();
    b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    b.sign(&root_key, MessageDigest::sha256()).unwrap();
    let intermediate = b.build();
    // The provisioning CA is trusted directly; the client's current
    // certificate comes from an intermediate only the client sends.
    let root_for_verifier = root.clone();
    let mut fx = Fx::with(rsa(2048), rsa(2048), move |ca| {
        verifier(vec![ca.clone(), root_for_verifier])
    });
    fx.f = leaf(&intermediate, &intermediate_key, &fx.f_key.clone(), &CLIENT);
    fx.channel = Channel {
        fingerprint: fingerprint(&fx.f),
        policy_fingerprint: fingerprint(&fx.f),
        certificate: fx.f.to_der().unwrap(),
        chain: vec![],
    };
    let request_ = csr(&rsa(2048), "client", "c", MessageDigest::sha256());
    // Without the intermediate the current certificate does not verify.
    assert_eq!(reason(&fx.send(&csr_message(V21, &request_))), 12);
    fx.channel.chain = vec![intermediate.to_der().unwrap()];
    let r = fx.send(&csr_message(V21, &request_));
    chains(&fx, &certificate_in(items(&r)[1]));
    assert_eq!(fx.lookup(&fx.f), Lookup::Retired);
}

#[test]
fn a_put_subscriber_never_receives_the_message_scoped_key() {
    let mut fx = Fx::new();
    let sent: Arc<Mutex<Vec<String>>> = Default::default();
    let sink = {
        let sent = sent.clone();
        Box::new(move |o: Outbound| {
            sent.lock().unwrap().push(format!(
                "{} {} {} {}",
                o.operation,
                o.object,
                o.owner,
                serde_json::to_string(&o.message).unwrap()
            ));
            true
        })
    };
    let subscriptions = [(
        OWNER.to_owned(),
        Subscription {
            version: V21,
            notify: true,
            put: true,
        },
    )]
    .into_iter()
    .collect();
    let p = fx.provisioning(verifier(vec![fx.ca.clone()]));
    fx.e = Engine::new(store(fx.dir.path()), true)
        .with_provisioning(p)
        .with_server_to_client(ServerToClient::new(subscriptions, sink).unwrap());
    let r = fx.send(&generated_message(V21));
    let key_id = uid_of(items(&r)[0]);
    let cert_id = certificate_link(V21, items(&r)[2]);
    let delivered = format!("{:?}", sent.lock().unwrap());
    // The subscriber hears of the certificate, never of the key.
    assert!(delivered.contains(&cert_id), "{delivered}");
    assert!(!delivered.contains(&key_id), "{delivered}");
    let material = hex::encode(key_material(items(&r)[1]));
    assert!(!delivered.contains(&material));
}

#[test]
fn startup_listing_explains_the_records_against_the_policy() {
    let mut fx = Fx::new();
    let request_ = csr(&rsa(2048), "client", "c", MessageDigest::sha256());
    let r = fx.send(&csr_message(V21, &request_));
    let n = certificate_in(items(&r)[1]);
    let (f, n) = (fingerprint(&fx.f), fingerprint(&n));
    let policy = |entries: &[(&str, &str)]| {
        entries
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect::<std::collections::HashMap<_, _>>()
    };
    let (records, warnings) = fx.e.provisioning_records(&policy(&[(&f, OWNER)])).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .any(|r| r.contains(&f) && r.contains("retired"))
    );
    assert!(
        records
            .iter()
            .any(|r| r.contains(&n) && r.contains("active"))
    );
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains(&format!("{f} anchors active {n}")),
        "{warnings:?}"
    );
    // Folded in under the same name: the anchor still warns until removed.
    let (_, warnings) =
        fx.e.provisioning_records(&policy(&[(&f, OWNER), (&n, OWNER)]))
            .unwrap();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    let (_, warnings) = fx.e.provisioning_records(&policy(&[(&n, OWNER)])).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    // Neither: the replacement is refused. Listed under another name: a
    // conflict.
    let (_, warnings) = fx.e.provisioning_records(&policy(&[])).unwrap();
    assert!(warnings[0].contains("refused"), "{warnings:?}");
    let (_, warnings) =
        fx.e.provisioning_records(&policy(&[(&f, OWNER), (&n, "mallory")]))
            .unwrap();
    assert!(
        warnings.iter().any(|w| w.contains("mallory")),
        "{warnings:?}"
    );
    // A retired fingerprint that anchors nothing: remove it.
    let channel = fx.channel_for(&certificate_in(items(&r)[1]));
    let r = fx.send_on(
        &channel,
        &csr_message(V21, &csr(&rsa(2048), "c", "d", MessageDigest::sha256())),
    );
    payload(items(&r)[1]);
    let (_, warnings) =
        fx.e.provisioning_records(&policy(&[(&f, OWNER), (&n, OWNER)]))
            .unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains(&n) && w.contains("remove it")),
        "{warnings:?}"
    );
}

#[test]
fn retirement_is_honoured_after_a_restart_without_the_provisioning_ca() {
    let mut fx = Fx::new();
    let request_ = csr(&rsa(2048), "client", "c", MessageDigest::sha256());
    let r = fx.send(&csr_message(V21, &request_));
    let n = certificate_in(items(&r)[1]);
    fx.reopen(false);
    assert_eq!(fx.lookup(&fx.f), Lookup::Retired);
    assert_ne!(fx.lookup(&n), Lookup::Unknown);
    // The new certificate sees the principal's objects.
    let channel = fx.channel_for(&n);
    let r = fx.send_on(&channel, &request(V21, vec![], vec![(8, vec![])]));
    assert_eq!(payload(items(&r)[0]).all(UNIQUE_IDENTIFIER).count(), 1);
}

#[test]
fn only_one_re_provision_runs_per_message_even_after_a_failure() {
    // Every issued leaf is refused, so each attempt fails after generating
    // and signing; its rollback must not allow another attempt.
    let issued = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = issued.clone();
    let mut fx = Fx::with(rsa(2048), rsa(2048), move |_| {
        Box::new(move |leaf: &X509, _: &[X509]| {
            if leaf.not_after() > Asn1Time::days_from_now(20).unwrap().as_ref() {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err("refused".into())
            } else {
                Ok(())
            }
        })
    });
    let attempt = || vec![(53, vec![]), (10, placeholder(V21)), link_attributes(V21)];
    let mut items_ = attempt();
    items_.extend(attempt());
    let r = fx.send(&request(
        V21,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1)],
        items_,
    ));
    let all = items(&r);
    assert_eq!(reason_of(all[0]), 10);
    assert_eq!(
        reason_of(all[3]),
        12,
        "a second Re-Provision in the message"
    );
    assert_eq!(issued.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_unchanged(&fx);
}

#[test]
fn the_certificate_identifier_must_reach_the_client() {
    // A Get Attributes that does not return the Link: the client would hold
    // a key without knowing its certificate. Nothing commits.
    let mut fx = Fx::with(rsa(2048), ec(Nid::X9_62_PRIME256V1), |ca| {
        verifier(vec![ca.clone()])
    });
    fx.ops = vec![10, 11, 53];
    let r = fx.send(&request(
        V21,
        vec![],
        vec![
            (53, vec![]),
            (10, vec![]),
            (
                11,
                vec![Node::enumeration(ATTRIBUTE_REFERENCE, OBJECT_TYPE)],
            ),
        ],
    ));
    let all = items(&r);
    assert_eq!(all.len(), 1, "{}", serde_json::to_string(&r).unwrap());
    assert_eq!(reason_of(all[0]), 7);
    assert_unchanged(&fx);
}

#[test]
fn nothing_may_remove_the_new_credential_in_its_message() {
    // Obliterate of the object the client still has to fetch is refused, so
    // the Get still delivers it and the replacement commits.
    for csr_form in [true, false] {
        let mut fx = Fx::with(rsa(2048), rsa(2048), |ca| verifier(vec![ca.clone()]));
        fx.ops.push(61);
        let first = if csr_form {
            let request_ = csr(&rsa(2048), "client", "c", MessageDigest::sha256());
            (53, vec![csr_field(&request_)])
        } else {
            (53, vec![])
        };
        let mut steps = vec![first, (61, placeholder(V3)), (10, placeholder(V3))];
        if !csr_form {
            steps.push(link_attributes(V3));
        }
        let r = fx.send(&request(
            V3,
            vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1)],
            steps,
        ));
        let all = items(&r);
        assert_eq!(reason_of(all[1]), 12);
        for item in all.iter().skip(2) {
            payload(item);
        }
        assert_eq!(fx.lookup(&fx.f), Lookup::Retired);
    }
}

#[test]
fn issued_certificates_are_backdated_for_clock_skew() {
    // notBefore a little in the past, so a verifier whose clock is a second
    // behind still accepts the certificate at once.
    let mut fx = Fx::new();
    let request_ = csr(&rsa(2048), "client", "c", MessageDigest::sha256());
    let r = fx.send(&csr_message(V21, &request_));
    let issued = certificate_in(items(&r)[1]);
    let now = Asn1Time::from_unix(keytend_kmip_server::store::now() - 60).unwrap();
    assert!(
        issued.not_before() <= now.as_ref(),
        "{}",
        issued.not_before()
    );
}

#[test]
fn only_retrievals_may_follow_a_re_provision_in_its_message() {
    // Later items could otherwise destroy the certificate the client still
    // has to fetch, after the guard saw the key and the identifier.
    let mut fx = Fx::with(rsa(2048), ec(Nid::X9_62_PRIME256V1), |ca| {
        verifier(vec![ca.clone()])
    });
    fx.ops = vec![8, 10, 11, 12, 19, 20, 53];
    let revoke = vec![Node::structure(
        REVOCATION_REASON,
        vec![Node::enumeration(REVOCATION_REASON_CODE, 2)],
    )];
    let r = fx.send(&request(
        V21,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1)],
        vec![
            (53, vec![]),
            (10, vec![]),
            link_attributes(V21),
            (12, vec![]),
            (
                8,
                vec![Node::structure(
                    ATTRIBUTES,
                    vec![Node::enumeration(OBJECT_TYPE, 1)],
                )],
            ),
            (19, revoke),
            (20, vec![]),
        ],
    ));
    let all = items(&r);
    let statuses: Vec<_> = all.iter().map(|i| status(i)).collect();
    assert_eq!(statuses, [0, 0, 0, 0, 1, 1, 1]);
    for item in &all[4..] {
        assert_eq!(reason_of(item), 12);
    }
    assert_eq!(fx.lookup(&fx.f), Lookup::Retired);
    // The certificate is still there for the next message.
    let certificate = certificate_link(V21, all[2]);
    let r = fx.send(&request(V21, vec![], vec![get(V21, &certificate)]));
    certificate_in(items(&r)[0]);
}

/// A connection whose certificate the store cannot check (the retirement
/// lookup fails, for example after a live history integrity failure) is not
/// admitted by the policy alone: its request gets General Failure in its own
/// version, with its Client Correlation Value.
#[test]
fn store_failure_response_is_a_versioned_general_failure() {
    use keytend_kmip_server::protocol::store_failure_response;
    let request = |major: i32, minor: i32| {
        Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(
                    REQUEST_HEADER,
                    vec![
                        Node::structure(
                            PROTOCOL_VERSION,
                            vec![
                                Node::int(PROTOCOL_VERSION_MAJOR, major),
                                Node::int(PROTOCOL_VERSION_MINOR, minor),
                            ],
                        ),
                        Node::text(CLIENT_CORRELATION_VALUE, "c-1"),
                        Node::int(BATCH_COUNT, 1),
                    ],
                ),
                Node::structure(BATCH_ITEM, vec![Node::enumeration(OPERATION, 10)]),
            ],
        )
    };
    let version = |r: &Node| {
        let v = r
            .required(RESPONSE_HEADER)
            .unwrap()
            .required(PROTOCOL_VERSION)
            .unwrap();
        (
            v.required(PROTOCOL_VERSION_MAJOR)
                .unwrap()
                .number()
                .unwrap(),
            v.required(PROTOCOL_VERSION_MINOR)
                .unwrap()
                .number()
                .unwrap(),
        )
    };
    let r = store_failure_response(&request(2, 1));
    assert_eq!(reason(&r), 0x100);
    assert_eq!(version(&r), (2, 1));
    assert!(
        r.required(RESPONSE_HEADER)
            .unwrap()
            .get(CLIENT_CORRELATION_VALUE)
            .is_some()
    );
    assert!(items(&r)[0].get(RESPONSE_PAYLOAD).is_none());
    // An unsupported version is answered in 1.4.
    assert_eq!(version(&store_failure_response(&request(9, 9))), (1, 4));
}

/// Unix seconds of an ASN.1 time.
fn unix(t: &openssl::asn1::Asn1TimeRef) -> i64 {
    let d = Asn1Time::from_unix(0).unwrap().diff(t).unwrap();
    i64::from(d.days) * 86_400 + i64::from(d.secs)
}
/// This server's Message Extension asking for a notAfter, added to the
/// first batch item (the Re-Provision).
fn with_extension(mut msg: Node, critical: bool, body: Vec<Node>) -> Node {
    let extension = Node::structure(
        MESSAGE_EXTENSION,
        vec![
            Node::text(VENDOR_IDENTIFICATION, "keytend_kmip_server"),
            Node::boolean(CRITICALITY_INDICATOR, critical),
            Node::structure(VENDOR_EXTENSION, body),
        ],
    );
    let keytend_kmip_server::ttlv::Value::Structure(fields) = &mut msg.value else {
        panic!("message")
    };
    let keytend_kmip_server::ttlv::Value::Structure(item) = &mut fields[1].value else {
        panic!("item")
    };
    item.push(extension);
    msg
}
fn date_attribute(fx: &mut Fx, v: Version, id: &str, tag: u32) -> Option<i64> {
    let r = fx.send(&request(v, vec![], vec![(11, vec![uid(v, id)])]));
    payload(items(&r)[0])
        .required(ATTRIBUTES)
        .unwrap()
        .get(tag)
        .map(|n| match n.value {
            keytend_kmip_server::ttlv::Value::DateTime(t) => t,
            _ => panic!("not a date"),
        })
}

// docs/re-provision.md#validity-period
#[test]
fn a_message_extension_sets_the_validity_of_issued_certificates() {
    let now = keytend_kmip_server::store::now;
    for v in [V20, V21, V3] {
        // Without the extension: a year, cut short at the CA's notAfter.
        let mut fx = Fx::new();
        let r = fx.send(&csr_message(
            v,
            &csr(&rsa(2048), "client", "x", MessageDigest::sha256()),
        ));
        let n = certificate_in(items(&r)[1]);
        assert_eq!(unix(n.not_after()), unix(fx.ca.not_after()));

        // The request form, Non-Critical: notAfter and Deactivation Date.
        let mut fx = Fx::new();
        let wanted = now() + 7 * 86_400;
        let msg = with_extension(
            csr_message(v, &csr(&rsa(2048), "client", "x", MessageDigest::sha256())),
            false,
            vec![Node::date(DEACTIVATION_DATE, wanted)],
        );
        let r = fx.send(&msg);
        let id = uid_of(items(&r)[0]);
        let n = certificate_in(items(&r)[1]);
        assert_eq!(unix(n.not_after()), wanted, "{v:?}");
        chains(&fx, &n);
        assert_eq!(
            date_attribute(&mut fx, v, &id, DEACTIVATION_DATE),
            Some(wanted)
        );

        // The no-parameter form, Critical: understood, so accepted.
        let mut fx = Fx::new();
        let wanted = now() + 86_400;
        let r = fx.send(&with_extension(
            generated_message(v),
            true,
            vec![Node::date(DEACTIVATION_DATE, wanted)],
        ));
        let cert_id = certificate_link(v, items(&r)[2]);
        let r = fx.send(&request(v, vec![], vec![get(v, &cert_id)]));
        assert_eq!(unix(certificate_in(items(&r)[0]).not_after()), wanted);

        // Refusals: Invalid Field, and nothing is written.
        let ca_end = unix(Fx::new().ca.not_after());
        for body in [
            vec![Node::date(DEACTIVATION_DATE, ca_end + 86_400)],
            vec![Node::date(DEACTIVATION_DATE, now() - 1)],
            vec![Node::date(ACTIVATION_DATE, now() + 60)],
            vec![
                Node::date(DEACTIVATION_DATE, now() + 60),
                Node::date(DEACTIVATION_DATE, now() + 90),
            ],
            vec![],
        ] {
            let mut fx = Fx::new();
            let r = fx.send(&with_extension(
                csr_message(v, &csr(&rsa(2048), "client", "x", MessageDigest::sha256())),
                false,
                body,
            ));
            assert_eq!(reason(&r), 7, "{v:?}");
            assert_unchanged(&fx);
        }
        // The certificate form has no period to set.
        let mut fx = Fx::new();
        let adopted = fx.issue(&rsa(2048), &CLIENT);
        let r = fx.send(&with_extension(
            request(v, vec![], vec![(53, vec![certificate_field(&adopted)])]),
            false,
            vec![Node::date(DEACTIVATION_DATE, now() + 60)],
        ));
        assert_eq!(reason(&r), 7);
        assert_unchanged(&fx);
    }
}
