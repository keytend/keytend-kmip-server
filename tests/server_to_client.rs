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

//! Server-to-client Notify and Put: message content after committed batches,
//! and delivery to a test listener over mutually authenticated TLS.
use keytend_kmip_server::{
    delivery::{self, Delivered, Dial, Endpoint, Limits, Transport},
    protocol::{Engine, Outbound, ServerToClient, Sink, Subscription, Version},
    store::Store,
    tags::*,
    ttlv::{self, Node},
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslMethod, SslVerifyMode},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName},
    },
};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Sent = Arc<Mutex<Vec<Outbound>>>;
struct Fixture {
    _dir: tempfile::TempDir,
    e: Engine,
    sent: Sent,
}
fn fixture(subscriptions: Vec<(&str, Version, bool, bool)>, accept: bool) -> Fixture {
    let d = tempfile::tempdir().unwrap();
    let master = d.path().join("master");
    std::fs::write(&master, [5; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Store::open(&d.path().join("store"), &master).unwrap();
    let sent = Sent::default();
    let sink = {
        let sent = sent.clone();
        Box::new(move |o: Outbound| {
            if accept {
                sent.lock().unwrap().push(o);
            }
            accept
        })
    };
    let subscriptions = subscriptions
        .into_iter()
        .map(|(owner, version, notify, put)| {
            (
                owner.to_owned(),
                Subscription {
                    version,
                    notify,
                    put,
                },
            )
        })
        .collect();
    Fixture {
        _dir: d,
        e: Engine::new(store, false)
            .with_server_to_client(ServerToClient::new(subscriptions, sink).unwrap()),
        sent,
    }
}
fn message(v: Version, items: Vec<(u32, Vec<Node>)>, continuation: Option<u32>) -> Node {
    let mut h = vec![v.node()];
    if let Some(c) = continuation {
        h.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, c));
    }
    h.push(Node::int(BATCH_COUNT, items.len() as i32));
    let mut f = vec![Node::structure(REQUEST_HEADER, h)];
    for (i, (op, p)) in items.into_iter().enumerate() {
        f.push(Node::structure(
            BATCH_ITEM,
            vec![
                Node::enumeration(OPERATION, op),
                Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8]),
                Node::structure(REQUEST_PAYLOAD, p),
            ],
        ));
    }
    Node::structure(REQUEST_MESSAGE, f)
}
fn call(f: &mut Fixture, v: Version, owner: &str, op: u32, p: Vec<Node>) -> Node {
    let r =
        f.e.process(owner, &message(v, vec![(op, p)], None))
            .unwrap();
    let item = r.get(BATCH_ITEM).unwrap();
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{}",
        serde_json::to_string(&r).unwrap()
    );
    item.required(RESPONSE_PAYLOAD).unwrap().clone()
}
fn attribute(v: Version, a: Node) -> Node {
    if v.0 >= 2 {
        return a;
    }
    let name = tag_name(a.tag).unwrap();
    let mut value = a;
    value.tag = ATTRIBUTE_VALUE;
    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), value])
}
fn create(f: &mut Fixture, v: Version, owner: &str, extra: Vec<Node>) -> String {
    let mut attrs = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    attrs.extend(extra);
    let container = if v.0 >= 2 {
        Node::structure(ATTRIBUTES, attrs)
    } else {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            attrs.into_iter().map(|a| attribute(v, a)).collect(),
        )
    };
    call(
        f,
        v,
        owner,
        1,
        vec![Node::enumeration(OBJECT_TYPE, 2), container],
    )
    .required(UNIQUE_IDENTIFIER)
    .unwrap()
    .string()
    .unwrap()
    .to_owned()
}
fn take(f: &Fixture) -> Vec<Outbound> {
    std::mem::take(&mut *f.sent.lock().unwrap())
}
/// Check the server-initiated request framing and return its payload.
fn request_payload(o: &Outbound, v: Version, op: u32) -> Node {
    assert_eq!(o.operation, op);
    let m = &o.message;
    assert_eq!(m.tag, REQUEST_MESSAGE);
    let header = m.required(REQUEST_HEADER).unwrap();
    let version = header.required(PROTOCOL_VERSION).unwrap();
    assert_eq!(
        (
            version
                .required(PROTOCOL_VERSION_MAJOR)
                .unwrap()
                .number()
                .unwrap(),
            version
                .required(PROTOCOL_VERSION_MINOR)
                .unwrap()
                .number()
                .unwrap()
        ),
        (v.0, v.1)
    );
    // 1.0 sections 5.1/5.2: these request header fields are not allowed.
    for tag in [
        MAXIMUM_RESPONSE_SIZE,
        ASYNCHRONOUS_INDICATOR,
        BATCH_ERROR_CONTINUATION_OPTION,
        BATCH_ORDER_OPTION,
    ] {
        assert!(header.get(tag).is_none());
    }
    let item = m.required(BATCH_ITEM).unwrap();
    assert_eq!(item.required(OPERATION).unwrap().number().unwrap(), op);
    item.required(REQUEST_PAYLOAD).unwrap().clone()
}
fn legacy_attribute<'a>(p: &'a Node, name: &str) -> Option<&'a Node> {
    p.all(ATTRIBUTE)
        .find(|a| a.required(ATTRIBUTE_NAME).unwrap().string().unwrap() == name)
}

#[test]
fn committed_changes_yield_put_and_notify_for_subscribed_owners_only() {
    let v = Version(1, 4);
    let mut f = fixture(vec![("alice", v, true, true)], true);
    let query = call(
        &mut f,
        v,
        "alice",
        24,
        vec![Node::enumeration(QUERY_FUNCTION, 1)],
    );
    let ops: Vec<u32> = query.all(OPERATION).map(|n| n.number().unwrap()).collect();
    assert!(ops.contains(&27) && ops.contains(&28));
    let query = call(
        &mut f,
        v,
        "bob",
        24,
        vec![Node::enumeration(QUERY_FUNCTION, 1)],
    );
    assert!(
        !query
            .all(OPERATION)
            .any(|n| [27, 28].contains(&n.number().unwrap()))
    );

    // Create: Put New carrying exactly the Get result and the attributes.
    let id = create(&mut f, v, "alice", vec![]);
    let sent = take(&f);
    assert_eq!(sent.len(), 1);
    let p = request_payload(&sent[0], v, 28);
    assert_eq!(p.required(UNIQUE_IDENTIFIER).unwrap().string().unwrap(), id);
    assert_eq!(p.required(PUT_FUNCTION).unwrap().number().unwrap(), 1);
    assert!(p.get(REPLACED_UNIQUE_IDENTIFIER).is_none());
    let got = call(
        &mut f,
        v,
        "alice",
        10,
        vec![Node::text(UNIQUE_IDENTIFIER, &id)],
    );
    assert!(p.required(SYMMETRIC_KEY).unwrap() == got.required(SYMMETRIC_KEY).unwrap());
    assert!(legacy_attribute(&p, "Cryptographic Algorithm").is_some());
    assert!(
        take(&f).iter().all(|o| o.operation == 27),
        "Get only changes metadata"
    );

    // Add Attribute: Notify with the new value and Last Change Date.
    call(
        &mut f,
        v,
        "alice",
        13,
        vec![
            Node::text(UNIQUE_IDENTIFIER, &id),
            attribute(v, Node::text(CONTACT_INFORMATION, "ops@example")),
        ],
    );
    let sent = take(&f);
    assert_eq!(sent.len(), 1);
    let p = request_payload(&sent[0], v, 27);
    assert_eq!(p.required(UNIQUE_IDENTIFIER).unwrap().string().unwrap(), id);
    let contact = legacy_attribute(&p, "Contact Information").unwrap();
    assert_eq!(
        contact.required(ATTRIBUTE_VALUE).unwrap().string().unwrap(),
        "ops@example"
    );
    assert!(legacy_attribute(&p, "Last Change Date").is_some());

    // Delete Attribute: the deleted instance has no Attribute Value (table 167).
    call(
        &mut f,
        v,
        "alice",
        15,
        vec![
            Node::text(UNIQUE_IDENTIFIER, &id),
            Node::text(ATTRIBUTE_NAME, "Contact Information"),
        ],
    );
    let sent = take(&f);
    let p = request_payload(&sent[0], v, 27);
    let gone = legacy_attribute(&p, "Contact Information").unwrap();
    assert!(gone.get(ATTRIBUTE_VALUE).is_none());

    // Re-key: Put Replace naming the replaced key, and Notify for the old key.
    call(
        &mut f,
        v,
        "alice",
        4,
        vec![Node::text(UNIQUE_IDENTIFIER, &id)],
    );
    let sent = take(&f);
    let put = sent.iter().find(|o| o.operation == 28).unwrap();
    let p = request_payload(put, v, 28);
    assert_eq!(p.required(PUT_FUNCTION).unwrap().number().unwrap(), 2);
    assert_eq!(
        p.required(REPLACED_UNIQUE_IDENTIFIER)
            .unwrap()
            .string()
            .unwrap(),
        id
    );
    let notify = sent.iter().find(|o| o.operation == 27).unwrap();
    assert_eq!(notify.object, id);
    assert!(legacy_attribute(&request_payload(notify, v, 27), "Link").is_some());

    // Sensitive or non-extractable material is never pushed.
    create(&mut f, v, "alice", vec![Node::boolean(SENSITIVE, true)]);
    create(&mut f, v, "alice", vec![Node::boolean(EXTRACTABLE, false)]);
    assert!(take(&f).iter().all(|o| o.operation != 28));

    // Another owner's objects produce nothing.
    create(&mut f, v, "bob", vec![]);
    assert!(take(&f).is_empty());

    // An undone batch commits nothing, so nothing leaves the server.
    let create_item = (
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            Node::structure(
                TEMPLATE_ATTRIBUTE,
                vec![
                    attribute(v, Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3)),
                    attribute(v, Node::int(CRYPTOGRAPHIC_LENGTH, 256)),
                ],
            ),
        ],
    );
    let r =
        f.e.process(
            "alice",
            &message(
                v,
                vec![
                    create_item,
                    (10, vec![Node::text(UNIQUE_IDENTIFIER, "missing")]),
                ],
                Some(3),
            ),
        )
        .unwrap();
    assert_eq!(
        r.get(BATCH_ITEM)
            .unwrap()
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
        3
    );
    assert!(take(&f).is_empty());
}

#[test]
fn version_2_notify_uses_attributes_and_references() {
    let v = Version(2, 1);
    let mut f = fixture(vec![("alice", v, true, false)], true);
    let id = create(&mut f, v, "alice", vec![]);
    assert!(take(&f).is_empty(), "Put is not subscribed");
    call(
        &mut f,
        v,
        "alice",
        13,
        vec![
            Node::text(UNIQUE_IDENTIFIER, &id),
            Node::structure(NEW_ATTRIBUTE, vec![Node::text(CONTACT_INFORMATION, "x")]),
        ],
    );
    let p = request_payload(&take(&f)[0], v, 27);
    let attrs = p.required(ATTRIBUTES).unwrap();
    assert_eq!(
        attrs
            .required(CONTACT_INFORMATION)
            .unwrap()
            .string()
            .unwrap(),
        "x"
    );
    assert!(attrs.get(LAST_CHANGE_DATE).is_some());
    call(
        &mut f,
        v,
        "alice",
        15,
        vec![
            Node::text(UNIQUE_IDENTIFIER, &id),
            Node::enumeration(ATTRIBUTE_REFERENCE, CONTACT_INFORMATION),
        ],
    );
    let p = request_payload(&take(&f)[0], v, 27);
    assert_eq!(
        p.required(ATTRIBUTE_REFERENCE).unwrap().number().unwrap(),
        CONTACT_INFORMATION
    );
    let query = call(
        &mut f,
        v,
        "alice",
        24,
        vec![Node::enumeration(QUERY_FUNCTION, 1)],
    );
    let ops: Vec<u32> = query.all(OPERATION).map(|n| n.number().unwrap()).collect();
    assert!(ops.contains(&27) && !ops.contains(&28));
}

#[test]
fn full_queue_never_fails_the_client_request() {
    let v = Version(1, 4);
    let mut f = fixture(vec![("alice", v, true, true)], false);
    create(&mut f, v, "alice", vec![]);
    assert!(take(&f).is_empty());
}

#[test]
fn draft_and_empty_subscriptions_are_rejected() {
    for (version, notify, put) in [(Version(3, 0), true, true), (Version(2, 1), false, false)] {
        let subscriptions = HashMap::from([(
            "alice".to_owned(),
            Subscription {
                version,
                notify,
                put,
            },
        )]);
        assert!(ServerToClient::new(subscriptions, Box::new(|_| true)).is_err());
    }
}

// ---- Transport -------------------------------------------------------------

struct Pki {
    dir: tempfile::TempDir,
    ca: X509,
    ca_key: PKey<Private>,
}
fn key() -> PKey<Private> {
    PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap()
}
fn certificate(
    cn: &str,
    key: &PKey<Private>,
    issuer: Option<(&X509, &PKey<Private>)>,
    server: bool,
) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(
        &BigNum::from_u32(rand_serial())
            .unwrap()
            .to_asn1_integer()
            .unwrap(),
    )
    .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(issuer.map(|(c, _)| c.subject_name()).unwrap_or(&name))
        .unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let mut bc = BasicConstraints::new();
    if issuer.is_none() {
        bc.ca();
    }
    b.append_extension(bc.build().unwrap()).unwrap();
    if issuer.is_some() {
        let mut eku = ExtendedKeyUsage::new();
        if server {
            eku.server_auth();
            b.append_extension(eku.build().unwrap()).unwrap();
            let san = SubjectAlternativeName::new()
                .ip("127.0.0.1")
                .dns("listener.test")
                .build(&b.x509v3_context(issuer.map(|(c, _)| c.as_ref()), None))
                .unwrap();
            b.append_extension(san).unwrap();
        } else {
            eku.client_auth();
            b.append_extension(eku.build().unwrap()).unwrap();
        }
    }
    b.sign(
        issuer.map(|(_, k)| k).unwrap_or(key),
        MessageDigest::sha256(),
    )
    .unwrap();
    b.build()
}
fn rand_serial() -> u32 {
    let mut b = [0; 4];
    openssl::rand::rand_bytes(&mut b).unwrap();
    u32::from_be_bytes(b) >> 1
}
impl Pki {
    fn new() -> Self {
        let ca_key = key();
        let ca = certificate("delivery test CA", &ca_key, None, false);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ca.pem"), ca.to_pem().unwrap()).unwrap();
        let p = Self { dir, ca, ca_key };
        p.issue("kms", false);
        p
    }
    fn issue(&self, name: &str, server: bool) -> (X509, PKey<Private>) {
        let k = key();
        let c = certificate(name, &k, Some((&self.ca, &self.ca_key)), server);
        std::fs::write(
            self.dir.path().join(format!("{name}.pem")),
            c.to_pem().unwrap(),
        )
        .unwrap();
        std::fs::write(
            self.dir.path().join(format!("{name}.key")),
            k.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        (c, k)
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }
    fn endpoint(&self, port: u16, server_name: &str, version: Version) -> Endpoint {
        Endpoint {
            dial: Some(Dial {
                address: format!("127.0.0.1:{port}"),
                server_name: server_name.to_owned(),
                connector: delivery::connector(
                    &self.path("ca.pem"),
                    &self.path("kms.pem"),
                    &self.path("kms.key"),
                )
                .unwrap(),
                transport: Transport::Ttlv,
            }),
            version,
        }
    }
}
/// How the test client endpoint answers. `versions`/`operations` None:
/// Discover Versions/Query fail with Operation Not Supported.
#[derive(Clone)]
struct Client {
    status: u32,
    versions: Option<Vec<Version>>,
    operations: Option<Vec<u32>>,
}
impl Client {
    fn accepting() -> Self {
        Self {
            status: 0,
            versions: Some(Version::supported(false)),
            operations: Some(vec![24, 27, 28, 30, 50]),
        }
    }
    fn legacy(status: u32) -> Self {
        Self {
            status,
            versions: None,
            operations: None,
        }
    }
    /// A KMIP client acting as the server for one request.
    fn respond(&self, request: &Node) -> Node {
        let rh = request.required(REQUEST_HEADER).unwrap();
        let item = request.required(BATCH_ITEM).unwrap();
        let op = item.required(OPERATION).unwrap().number().unwrap();
        let payload = item.required(REQUEST_PAYLOAD).unwrap();
        let mut fields = vec![item.required(OPERATION).unwrap().clone()];
        let answer = match op {
            30 => self.versions.as_ref().map(|versions| {
                // 6.2.1: only versions both sides support, in the offer's order.
                payload
                    .all(PROTOCOL_VERSION)
                    .filter(|n| versions.iter().any(|v| v.node() == **n))
                    .cloned()
                    .collect::<Vec<_>>()
            }),
            24 => self.operations.as_ref().map(|ops| {
                ops.iter()
                    .map(|op| Node::enumeration(OPERATION, *op))
                    .collect()
            }),
            50 if self.status == 0 => Some(vec![payload.required(ENDPOINT_ROLE).unwrap().clone()]),
            _ if self.status == 0 => Some(vec![]),
            _ => None,
        };
        match answer {
            Some(p) => {
                fields.push(Node::enumeration(RESULT_STATUS, 0));
                if !p.is_empty() {
                    fields.push(Node::structure(RESPONSE_PAYLOAD, p));
                }
            }
            None => {
                fields.push(Node::enumeration(RESULT_STATUS, 1));
                fields.push(Node::enumeration(RESULT_REASON, 5));
            }
        }
        Node::structure(
            RESPONSE_MESSAGE,
            vec![
                Node::structure(
                    RESPONSE_HEADER,
                    vec![
                        rh.required(PROTOCOL_VERSION).unwrap().clone(),
                        Node::date(TIME_STAMP, 0),
                        Node::int(BATCH_COUNT, 1),
                    ],
                ),
                Node::structure(BATCH_ITEM, fields),
            ],
        )
    }
}
async fn read_message<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Option<Node> {
    let mut header = [0; 8];
    s.read_exact(&mut header).await.ok()?;
    let mut data = vec![0; ttlv::frame_length(&header).unwrap()];
    data[..8].copy_from_slice(&header);
    s.read_exact(&mut data[8..]).await.ok()?;
    Some(ttlv::decode(&data).unwrap())
}
type Seen = Arc<Mutex<Vec<(Node, String)>>>;
/// A KMIP client endpoint: requires the CA-issued client certificate, records
/// each decoded request of each connection and answers as `client`.
async fn listener(pki: &Pki, client: Client) -> (u16, Seen) {
    let (cert, key) = pki.issue("listener", true);
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_ca_file(pki.path("ca.pem")).unwrap();
    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    let acceptor = Arc::new(acceptor.build());
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let seen = Seen::default();
    let record = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = socket.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let record = record.clone();
            let client = client.clone();
            tokio::spawn(async move {
                let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut s = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
                if Pin::new(&mut s).accept().await.is_err() {
                    return;
                }
                let peer = s
                    .ssl()
                    .peer_certificate()
                    .unwrap()
                    .subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .unwrap()
                    .data()
                    .to_string()
                    .unwrap();
                while let Some(request) = read_message(&mut s).await {
                    let response = client.respond(&request);
                    record.lock().unwrap().push((request, peer.clone()));
                    s.write_all(&response.encode()).await.unwrap();
                }
                let _ = s.shutdown().await;
            });
        }
    });
    (port, seen)
}
fn operations(seen: &Seen) -> Vec<u32> {
    seen.lock()
        .unwrap()
        .iter()
        .map(|(m, _)| {
            m.required(BATCH_ITEM)
                .unwrap()
                .required(OPERATION)
                .unwrap()
                .number()
                .unwrap()
        })
        .collect()
}
fn outbound(owner: &str, v: Version) -> Outbound {
    let mut f = fixture(vec![(owner, v, true, true)], true);
    create(&mut f, v, owner, vec![]);
    take(&f).pop().unwrap()
}
fn quick() -> Limits {
    Limits {
        queue: 4,
        attempts: 2,
        backoff: Duration::from_millis(10),
        connect_timeout: Duration::from_secs(2),
        io_timeout: Duration::from_secs(2),
        reverse_idle: Duration::from_millis(300),
        reverse_hold: Duration::from_secs(5),
    }
}
type Reports = tokio::sync::mpsc::UnboundedReceiver<Delivered>;
fn started(endpoint: Endpoint, owner: &str) -> (delivery::Reverse, Sink, Reports) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let (sink, reverse) = delivery::start(
        HashMap::from([(owner.to_owned(), endpoint)]),
        quick(),
        Arc::new(move |d| {
            let _ = tx.send(d);
        }),
    );
    (reverse, sink, rx)
}
async fn report(rx: &mut Reports) -> Delivered {
    tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .unwrap()
        .unwrap()
}
/// Deliver one message; return every report up to and including its own.
async fn deliver_all(endpoint: Endpoint, message: Outbound) -> Vec<Delivered> {
    let (_reverse, sink, mut rx) = started(endpoint, &message.endpoint.clone());
    assert!(sink(message));
    let mut reports = vec![];
    loop {
        let d = report(&mut rx).await;
        let done = d.object.is_some();
        reports.push(d);
        if done {
            return reports;
        }
    }
}
async fn deliver(endpoint: Endpoint, message: Outbound) -> Delivered {
    deliver_all(endpoint, message).await.pop().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn put_is_delivered_over_mutual_tls_and_decoded_by_the_listener() {
    let pki = Pki::new();
    let (port, seen) = listener(&pki, Client::accepting()).await;
    for v in [Version(1, 0), Version(2, 1)] {
        let message = outbound("alice", v);
        let expected = message.message.clone();
        let id = message.object.clone();
        let d = deliver(pki.endpoint(port, "127.0.0.1", v), message).await;
        assert!(d.outcome.is_ok(), "{:?}", d.outcome);
        assert_eq!((d.operation, d.object.as_deref()), (28, Some(id.as_str())));
        let (received, peer) = seen.lock().unwrap().pop().unwrap();
        assert!(
            received == expected,
            "listener decoded a different TTLV message"
        );
        assert_eq!(peer, "kms", "server must present its client certificate");
        assert_eq!(
            received
                .required(BATCH_ITEM)
                .unwrap()
                .required(REQUEST_PAYLOAD)
                .unwrap()
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .string()
                .unwrap(),
            id
        );
    }
}

// REQ:fa8b3a68ba0235ff 2.x Quantum Safe profile: the server sends Put and Notify to a subscribed client endpoint over mutual TLS
#[tokio::test(flavor = "multi_thread")]
async fn version_2_put_and_notify_are_delivered_over_mutual_tls() {
    let pki = Pki::new();
    let (port, seen) = listener(&pki, Client::accepting()).await;
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = fixture(vec![("alice", v, true, true)], true);
        let id = create(&mut f, v, "alice", vec![]);
        call(
            &mut f,
            v,
            "alice",
            13,
            vec![
                Node::text(UNIQUE_IDENTIFIER, &id),
                Node::structure(NEW_ATTRIBUTE, vec![Node::text(CONTACT_INFORMATION, "y")]),
            ],
        );
        let sent = take(&f);
        assert_eq!(
            sent.iter().map(|o| o.operation).collect::<Vec<_>>(),
            [28, 27],
            "{}.{}: Put for the new object, then Notify for the change",
            v.0,
            v.1
        );
        for message in sent {
            let operation = message.operation;
            request_payload(&message, v, operation);
            let expected = message.message.clone();
            let d = deliver(pki.endpoint(port, "127.0.0.1", v), message).await;
            assert!(d.outcome.is_ok(), "{:?}", d.outcome);
            // 2.x sessions first probe with Discover Versions and Query; the
            // last report and the last received message are the delivery itself.
            assert_eq!(
                (d.operation, d.object.as_deref()),
                (operation, Some(id.as_str()))
            );
            let (received, peer) = seen.lock().unwrap().pop().unwrap();
            assert!(received == expected, "listener decoded a different message");
            assert_eq!(peer, "kms");
        }
    }
}

// REQ:84d6ba52cfd06ec5 Discover Versions offers the server versions by preference
// REQ:4546b8e550e099b8 server-to-client Query names one Query Function
#[tokio::test(flavor = "multi_thread")]
async fn version_2_sessions_discover_versions_and_query_before_the_first_message() {
    let pki = Pki::new();
    let v = Version(2, 0);
    let (port, seen) = listener(&pki, Client::accepting()).await;
    let reports = deliver_all(pki.endpoint(port, "127.0.0.1", v), outbound("alice", v)).await;
    let ops = reports.iter().map(|d| d.operation).collect::<Vec<_>>();
    assert_eq!(ops, [30, 24, 28]);
    assert!(reports.iter().all(|d| d.outcome.is_ok()));
    assert!(
        reports[..2]
            .iter()
            .all(|d| d.object.is_none() && d.owner == "alice")
    );
    // One connection: Discover Versions, Query, then the Put.
    assert_eq!(operations(&seen), [30, 24, 28]);
    let seen = seen.lock().unwrap();
    let dv = seen[0].0.required(BATCH_ITEM).unwrap();
    let offered = dv
        .required(REQUEST_PAYLOAD)
        .unwrap()
        .all(PROTOCOL_VERSION)
        .cloned()
        .collect::<Vec<_>>();
    // The endpoint version is preferred, then the other final editions.
    let expected = delivery::offered_versions(v);
    assert_eq!(expected[..3], [Version(2, 0), Version(2, 1), Version(1, 4)]);
    assert!(offered == expected.iter().map(|v| v.node()).collect::<Vec<_>>());
    assert!(!expected.contains(&Version(3, 0)));
    let query = seen[1].0.required(BATCH_ITEM).unwrap();
    assert_eq!(
        query
            .required(REQUEST_PAYLOAD)
            .unwrap()
            .required(QUERY_FUNCTION)
            .unwrap()
            .number()
            .unwrap(),
        1
    );
    // 2.1 6.2: the request header carries Protocol Version and Batch Count only.
    let header = seen[0].0.required(REQUEST_HEADER).unwrap();
    assert_eq!(header.children().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn clients_that_lack_the_version_or_operation_get_no_message() {
    let pki = Pki::new();
    let v = Version(2, 1);
    let mut old = Client::accepting();
    old.versions = Some(vec![Version(1, 4)]);
    let (port, seen) = listener(&pki, old).await;
    let d = deliver(pki.endpoint(port, "127.0.0.1", v), outbound("alice", v)).await;
    assert!(
        d.outcome
            .unwrap_err()
            .contains("does not support protocol 2.1")
    );
    assert!(!operations(&seen).contains(&28));
    let mut no_put = Client::accepting();
    no_put.operations = Some(vec![27]);
    let (port, seen) = listener(&pki, no_put).await;
    let d = deliver(pki.endpoint(port, "127.0.0.1", v), outbound("alice", v)).await;
    assert!(
        d.outcome
            .unwrap_err()
            .contains("does not support operation 28")
    );
    assert!(!operations(&seen).contains(&28));
    // A client without Discover Versions or Query still gets the message.
    let (port, seen) = listener(&pki, Client::legacy(0)).await;
    let reports = deliver_all(pki.endpoint(port, "127.0.0.1", v), outbound("alice", v)).await;
    assert!(reports.last().unwrap().outcome.is_ok());
    assert!(reports[..2].iter().all(|d| d.outcome.is_ok()));
    assert_eq!(operations(&seen), [30, 24, 28]);
}

#[test]
fn discovered_versions_must_come_from_the_offer() {
    // REQ:0626b43f1a79d0d4 only versions supported by both sides are accepted
    let offered = delivery::offered_versions(Version(2, 1));
    let payload = |versions: &[Version]| {
        Node::structure(
            RESPONSE_PAYLOAD,
            versions.iter().map(|v| v.node()).collect(),
        )
    };
    let both = [Version(2, 1), Version(1, 4)];
    assert_eq!(
        delivery::discovered_versions(Some(&payload(&both)), &offered).unwrap(),
        both
    );
    assert!(delivery::discovered_versions(Some(&payload(&[Version(3, 0)])), &offered).is_err());
    assert!(
        delivery::discovered_versions(Some(&payload(&[Version(1, 4), Version(1, 4)])), &offered)
            .is_err()
    );
    assert!(
        delivery::discovered_versions(None, &offered)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_unreachable_or_misnamed_endpoints_fail_and_are_reported() {
    let pki = Pki::new();
    let v = Version(1, 4);
    // A client failure status is final: one attempt, reported as failed.
    let (port, seen) = listener(&pki, Client::legacy(1)).await;
    let d = deliver(pki.endpoint(port, "127.0.0.1", v), outbound("alice", v)).await;
    assert!(d.outcome.unwrap_err().contains("result status 1"));
    assert_eq!(seen.lock().unwrap().len(), 1);
    // The endpoint certificate must match the configured name.
    let (port, seen) = listener(&pki, Client::accepting()).await;
    let d = deliver(pki.endpoint(port, "other.test", v), outbound("alice", v)).await;
    assert!(d.outcome.is_err());
    assert!(seen.lock().unwrap().is_empty());
    // Nothing listening: bounded retries, then a failure report.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let d = deliver(pki.endpoint(port, "127.0.0.1", v), outbound("alice", v)).await;
    assert!(d.outcome.is_err());
    // Messages for an owner without an endpoint are refused, never queued.
    let (sink, _) = delivery::start(HashMap::new(), quick(), Arc::new(|_| {}));
    assert!(!sink(outbound("alice", v)));
    // Without an address or a reversed channel nothing can carry a message.
    let d = deliver(
        Endpoint {
            dial: None,
            version: Version(2, 1),
        },
        outbound("alice", Version(2, 1)),
    )
    .await;
    assert!(d.outcome.unwrap_err().contains("no reversed channel"));
}

/// The peer of a reversed channel: the KMIP client, now answering requests.
async fn reversed_client<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut s: S,
    client: Client,
) -> Vec<Node> {
    let mut seen = vec![];
    while let Some(request) = read_message(&mut s).await {
        let response = client.respond(&request);
        s.write_all(&response.encode()).await.unwrap();
        let op = request
            .required(BATCH_ITEM)
            .unwrap()
            .required(OPERATION)
            .unwrap()
            .number()
            .unwrap();
        seen.push(request);
        if op == 50 {
            break;
        }
    }
    seen
}
fn op_of(m: &Node) -> u32 {
    m.required(BATCH_ITEM)
        .unwrap()
        .required(OPERATION)
        .unwrap()
        .number()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reversed_channel_carries_messages_and_hands_the_roles_back() {
    let v = Version(2, 1);
    // No dial-out address: only the reversed channel can deliver.
    let (reverse, sink, mut rx) = started(
        Endpoint {
            dial: None,
            version: v,
        },
        "alice",
    );
    assert!(reverse.configured("alice") && !reverse.configured("bob"));
    let (server, peer) = tokio::io::duplex(1 << 20);
    let client = tokio::spawn(reversed_client(peer, Client::accepting()));
    let serving = tokio::spawn({
        let reverse = reverse.clone();
        async move {
            let mut server = server;
            reverse.serve("alice", &mut server).await
        }
    });
    // Probes run first on the open channel; a queued message waits for them.
    assert_eq!(report(&mut rx).await.operation, 30);
    assert_eq!(report(&mut rx).await.operation, 24);
    let message = outbound("alice", v);
    let id = message.object.clone();
    assert!(sink(message));
    let d = report(&mut rx).await;
    assert_eq!((d.operation, d.object.as_deref()), (28, Some(id.as_str())));
    assert!(d.outcome.is_ok(), "{:?}", d.outcome);
    // Idle: Set Endpoint Role (Client) hands the roles back.
    let d = report(&mut rx).await;
    assert_eq!((d.operation, d.object.as_deref()), (50, None));
    assert!(d.outcome.is_ok());
    serving.await.unwrap().unwrap();
    let seen = client.await.unwrap();
    assert_eq!(seen.iter().map(op_of).collect::<Vec<_>>(), [30, 24, 28, 50]);
    let handback = seen[3].required(BATCH_ITEM).unwrap();
    assert_eq!(
        handback
            .required(REQUEST_PAYLOAD)
            .unwrap()
            .required(ENDPOINT_ROLE)
            .unwrap()
            .number()
            .unwrap(),
        1,
        "the client is asked to apply the Client role"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reversed_channel_whose_client_lacks_the_version_is_handed_back_at_once() {
    let v = Version(2, 1);
    let (reverse, _sink, mut rx) = started(
        Endpoint {
            dial: None,
            version: v,
        },
        "alice",
    );
    let mut old = Client::accepting();
    old.versions = Some(vec![Version(2, 0)]);
    let (server, peer) = tokio::io::duplex(1 << 20);
    let client = tokio::spawn(reversed_client(peer, old));
    let mut server = server;
    reverse.serve("alice", &mut server).await.unwrap();
    let seen = client.await.unwrap();
    assert_eq!(seen.iter().map(op_of).collect::<Vec<_>>(), [30, 24, 50]);
    for op in [30, 24, 50] {
        assert_eq!(report(&mut rx).await.operation, op);
    }
    // A peer that refuses the hand-back closes the connection.
    let (server, mut peer) = tokio::io::duplex(1 << 20);
    let refusing = tokio::spawn(async move {
        let client = Client::accepting();
        while let Some(request) = read_message(&mut peer).await {
            let mut response = client.respond(&request);
            if op_of(&request) == 50 {
                response = Client::legacy(1).respond(&request);
            }
            peer.write_all(&response.encode()).await.unwrap();
        }
    });
    let mut server = server;
    assert!(reverse.serve("alice", &mut server).await.is_err());
    drop(server);
    refusing.await.unwrap();
}

#[test]
fn response_checks_follow_the_request() {
    let v = Version(1, 2);
    let ok = Node::structure(
        RESPONSE_MESSAGE,
        vec![
            Node::structure(RESPONSE_HEADER, vec![v.node(), Node::int(BATCH_COUNT, 1)]),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, 27),
                    Node::enumeration(RESULT_STATUS, 0),
                ],
            ),
        ],
    );
    assert!(delivery::check_response(&ok, v, 27).is_ok());
    assert!(delivery::check_response(&ok, v, 28).is_err());
    assert!(delivery::check_response(&ok, Version(1, 3), 27).is_err());
}

// REQ:d6c5ff2a425a8e78 the Put Function the server sends is New or Replace
// REQ:ccde7503344a1c80 a Replace Put names the replaced object
// REQ:2f245a01d1b47949 1.x Notify of a deleted attribute carries no Attribute Value
#[test]
fn put_functions_and_deleted_attribute_notices_in_every_edition() {
    for v in [
        Version(1, 0),
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
    ] {
        let mut f = fixture(vec![("alice", v, true, true)], true);
        let id = create(
            &mut f,
            v,
            "alice",
            vec![Node::text(CONTACT_INFORMATION, "c")],
        );
        let sent = take(&f);
        let p = request_payload(sent.iter().find(|o| o.operation == 28).unwrap(), v, 28);
        assert_eq!(p.required(PUT_FUNCTION).unwrap().number().unwrap(), 1);
        assert!(p.get(REPLACED_UNIQUE_IDENTIFIER).is_none());
        let new = call(
            &mut f,
            v,
            "alice",
            4,
            vec![Node::text(UNIQUE_IDENTIFIER, &id)],
        );
        let sent = take(&f);
        let p = request_payload(sent.iter().find(|o| o.operation == 28).unwrap(), v, 28);
        assert_eq!(p.required(PUT_FUNCTION).unwrap().number().unwrap(), 2);
        assert_eq!(
            p.required(REPLACED_UNIQUE_IDENTIFIER)
                .unwrap()
                .string()
                .unwrap(),
            id
        );
        assert_eq!(
            p.required(UNIQUE_IDENTIFIER).unwrap().string().unwrap(),
            new.required(UNIQUE_IDENTIFIER).unwrap().string().unwrap()
        );
        if v.0 == 1 {
            call(
                &mut f,
                v,
                "alice",
                15,
                vec![
                    Node::text(UNIQUE_IDENTIFIER, &id),
                    Node::text(ATTRIBUTE_NAME, "Contact Information"),
                ],
            );
            let sent = take(&f);
            let p = request_payload(sent.iter().find(|o| o.operation == 27).unwrap(), v, 27);
            let gone = legacy_attribute(&p, "Contact Information").unwrap();
            assert!(gone.get(ATTRIBUTE_VALUE).is_none());
        }
    }
}

// ---------- HTTPS delivery (Profiles 1.3-2.1 section 5.3) ----------

/// How the test HTTPS endpoint answers each POST.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Http {
    /// HTTP/1.1 200 with the 5.3.2 headers on a persistent connection.
    KeepAlive,
    /// The same, then "Connection: close" and the connection is closed.
    Close,
    /// Another status code, without a KMIP body.
    Status(u16),
    /// 200 with Content-Type text/plain.
    WrongType,
    /// 200 without Content-Length, delimited by closing the connection.
    NoLength,
}
/// One request as the endpoint received it.
struct Posted {
    request_line: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    connection: usize,
}
type Posts = Arc<Mutex<Vec<Posted>>>;
async fn read_http_request<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
) -> Option<(String, HashMap<String, String>, Vec<u8>)> {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8(head).unwrap();
    let mut lines = text.trim_end().split("\r\n");
    let request_line = lines.next().unwrap().to_owned();
    let headers: HashMap<_, _> = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.to_ascii_lowercase(), v.trim().to_owned())
        })
        .collect();
    let mut body = vec![0; headers["content-length"].parse().unwrap()];
    s.read_exact(&mut body).await.ok()?;
    Some((request_line, headers, body))
}
/// A KMIP client's HTTPS listener (the client acts as the HTTPS server,
/// 5.3.1): mutual TLS as for `listener`, then HTTP/1.1 requests.
async fn https_listener(pki: &Pki, client: Client, mode: Http) -> (u16, Posts) {
    let (cert, key) = pki.issue("listener", true);
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_ca_file(pki.path("ca.pem")).unwrap();
    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    let acceptor = Arc::new(acceptor.build());
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let posts = Posts::default();
    let record = posts.clone();
    tokio::spawn(async move {
        for connection in 0.. {
            let Ok((tcp, _)) = socket.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let record = record.clone();
            let client = client.clone();
            tokio::spawn(async move {
                let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut s = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
                if Pin::new(&mut s).accept().await.is_err() {
                    return;
                }
                while let Some((request_line, headers, body)) = read_http_request(&mut s).await {
                    let response = client.respond(&ttlv::decode(&body).unwrap()).encode();
                    record.lock().unwrap().push(Posted {
                        request_line,
                        headers,
                        body,
                        connection,
                    });
                    let ok = |extra: &str, kind: &str| {
                        let mut m = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\n{extra}\r\n",
                            response.len()
                        )
                        .into_bytes();
                        m.extend_from_slice(&response);
                        m
                    };
                    let (bytes, close) = match mode {
                        Http::KeepAlive => (ok("", "application/octet-stream"), false),
                        Http::Close => (
                            ok("Connection: close\r\n", "application/octet-stream"),
                            true,
                        ),
                        Http::WrongType => (ok("", "text/plain"), false),
                        Http::Status(code) => (
                            format!("HTTP/1.1 {code} Error\r\nContent-Length: 0\r\n\r\n")
                                .into_bytes(),
                            false,
                        ),
                        Http::NoLength => {
                            let mut m = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n".to_vec();
                            m.extend_from_slice(&response);
                            (m, true)
                        }
                    };
                    s.write_all(&bytes).await.unwrap();
                    if close {
                        break;
                    }
                }
                let _ = s.shutdown().await;
            });
        }
    });
    (port, posts)
}
fn https(pki: &Pki, port: u16, v: Version, target: &str) -> Endpoint {
    let mut endpoint = pki.endpoint(port, "127.0.0.1", v);
    endpoint.dial.as_mut().unwrap().transport = Transport::Https {
        target: target.to_owned(),
    };
    endpoint
}

// REQ:88648587bbe74f01 a server with server-to-client operations acts as an HTTPS client (transport "https"):
//   POST to the target URI with the TTLV Content-Type, Content-Length and Cache-Control no-cache, binary TTLV
//   body; only a 200 response with a Content-Length-framed TTLV body counts as the client's answer
#[tokio::test(flavor = "multi_thread")]
async fn https_endpoints_receive_put_as_http_posts() {
    let pki = Pki::new();
    for v in [Version(1, 4), Version(2, 1)] {
        for (mode, target) in [(Http::KeepAlive, "/kmip"), (Http::Close, "/kms/push")] {
            let (port, posts) = https_listener(&pki, Client::accepting(), mode).await;
            let message = outbound("alice", v);
            let expected = message.message.clone();
            let reports = deliver_all(https(&pki, port, v, target), message).await;
            for d in &reports {
                assert!(d.outcome.is_ok(), "{:?}", d.outcome);
            }
            let posts = posts.lock().unwrap();
            // 2.x sessions first discover the client's versions and operations.
            let ops: Vec<u32> = posts
                .iter()
                .map(|p| op_of(&ttlv::decode(&p.body).unwrap()))
                .collect();
            assert_eq!(ops, if v.0 >= 2 { vec![30, 24, 28] } else { vec![28] });
            for p in posts.iter() {
                assert_eq!(p.request_line, format!("POST {target} HTTP/1.1"));
                assert_eq!(p.headers["content-type"], "application/octet-stream");
                assert_eq!(p.headers["content-length"], p.body.len().to_string());
                assert_eq!(p.headers["cache-control"], "no-cache");
                assert_eq!(p.headers["host"], format!("127.0.0.1:{port}"));
            }
            assert!(ttlv::decode(&posts.last().unwrap().body).unwrap() == expected);
            // A persistent connection carries the whole session; a closed
            // one is reopened for the next request.
            let connections: std::collections::BTreeSet<_> =
                posts.iter().map(|p| p.connection).collect();
            assert_eq!(
                connections.len(),
                if mode == Http::KeepAlive {
                    1
                } else {
                    posts.len()
                }
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn https_answers_other_than_a_framed_ttlv_200_fail() {
    let pki = Pki::new();
    let v = Version(1, 4);
    // (mode, attempts): a server error is retried, a client error is final.
    for (mode, attempts, expected) in [
        (Http::Status(500), 2, "HTTP status 500"),
        (Http::Status(404), 1, "HTTP status 404"),
        (Http::WrongType, 1, "Content-Type"),
        (Http::NoLength, 1, "Content-Length"),
    ] {
        let (port, posts) = https_listener(&pki, Client::accepting(), mode).await;
        let d = deliver(https(&pki, port, v, "/kmip"), outbound("alice", v)).await;
        let error = d.outcome.unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert_eq!(posts.lock().unwrap().len(), attempts, "{error}");
    }
    // A TTLV-only listener does not speak HTTP: the exchange fails.
    let (port, _) = listener(&pki, Client::accepting()).await;
    let d = deliver(https(&pki, port, v, "/kmip"), outbound("alice", v)).await;
    assert!(d.outcome.is_err());
}
