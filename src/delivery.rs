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

//! Bounded delivery of server-to-client messages.
//!
//! Each configured principal has one endpoint, one bounded queue and one
//! worker. A message travels over one of two transports:
//!
//! - a reversed channel: a TTLV connection of the principal on which a
//!   client-to-server Set Endpoint Role made the server the client (2.0
//!   6.1.48; 2.1 6.1.54). It is preferred while one is open;
//! - otherwise a dial-out connection, when an address is configured: the
//!   server connects with mutually authenticated TLS (its own client
//!   certificate; the endpoint must chain to the configured CA and match the
//!   configured name). The connection carries binary TTLV, or with
//!   [`Transport::Https`] HTTP/1.1 POST requests: Profiles 1.3-2.1 section
//!   5.3.2 has an HTTPS server that supports server-to-client operations
//!   "behave as a HTTPS client", which section 5.3.1 describes.
//!
//! Each request requires a Response Message with Result Status Success
//! (1.0 sections 5.1-5.2: "The client SHALL send a response"). Transport
//! failures are retried a bounded number of times with backoff; a client
//! failure status is final. Every outcome is reported once so the caller can
//! audit it. Nothing here waits on, or holds, the engine.
//!
//! For 2.x endpoints a session first asks the client for its protocol
//! versions and operations with the server-to-client Discover Versions and
//! Query (2.1 sections 6.2.1 and 6.2.4): on the first dial-out connection,
//! again after any failure, and at the start of every reversed channel. A
//! client that answers that it supports neither the endpoint version nor the
//! operation gets no message; a client that answers Operation Not Supported
//! to a probe is treated as not having said, so delivery proceeds as
//! configured. 1.x defines no such operations (1.4 section 5), so 1.x
//! endpoints are not probed. A reversed channel is handed back with the
//! server-to-client Set Endpoint Role (2.1 section 6.2.5).
use crate::{
    protocol::{Outbound, ROLE_CLIENT, SET_ENDPOINT_ROLE, Sink, Version},
    tags::*,
    ttlv::{self, Node, Value},
};
use anyhow::{Context, Result, bail, ensure};
use openssl::{
    ssl::{SslConnector, SslFiletype, SslMethod, SslOptions, SslVersion},
    x509::{X509, store::X509StoreBuilder},
};
use std::{
    collections::HashMap,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, oneshot},
    time::{Instant, timeout},
};
use tokio_openssl::SslStream;
use zeroize::Zeroizing;

/// Server-to-client Discover Versions and Query (2.1 table 470).
pub const DISCOVER_VERSIONS: u32 = 0x1e;
pub const QUERY: u32 = 0x18;
/// Query Function Query Operations (2.1 table 486).
const QUERY_OPERATIONS: u32 = 1;
/// Result Reason Operation Not Supported.
const OPERATION_NOT_SUPPORTED: u32 = 5;

/// Where the server dials the client's KMIP listener.
pub struct Dial {
    /// host:port of the client's listener.
    pub address: String,
    /// DNS name or IP address that the endpoint certificate must match.
    pub server_name: String,
    pub connector: SslConnector,
    pub transport: Transport,
}
/// How a dial-out connection carries messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Binary TTLV messages directly over TLS.
    Ttlv,
    /// HTTP/1.1 over TLS (Profiles 1.3-2.1 section 5.3.1, which the HTTPS
    /// server follows as a client by section 5.3.2): each message is the body
    /// of a POST to `target`.
    Https { target: String },
}
/// The target URI the HTTPS profiles recommend (5.3.1/5.3.2 "SHOULD support
/// the value /kmip").
pub const HTTPS_TARGET: &str = "/kmip";
/// Whether `target` can be sent as an HTTP origin-form request target.
pub fn valid_target(target: &str) -> bool {
    target.starts_with('/') && target.len() <= 1024 && target.bytes().all(|b| b.is_ascii_graphic())
}
pub struct Endpoint {
    /// None: messages travel only over a reversed channel.
    pub dial: Option<Dial>,
    pub version: Version,
}
#[derive(Clone, Copy)]
pub struct Limits {
    pub queue: usize,
    pub attempts: u32,
    pub backoff: Duration,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    /// A reversed channel is handed back after this long without a message.
    pub reverse_idle: Duration,
    /// and at the latest after this long in total.
    pub reverse_hold: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            queue: 256,
            attempts: 3,
            backoff: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(10),
            reverse_idle: Duration::from_secs(30),
            reverse_hold: Duration::from_secs(120),
        }
    }
}
/// One outcome. Probes and hand-backs name no object.
pub struct Delivered {
    pub owner: String,
    pub operation: u32,
    pub object: Option<String>,
    pub outcome: std::result::Result<(), String>,
}
pub type Report = Arc<dyn Fn(Delivered) + Send + Sync>;

/// TLS client context trusting only `ca`, presenting `certificate`/`key`.
pub fn connector(ca: &Path, certificate: &Path, key: &Path) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_options(SslOptions::NO_COMPRESSION | SslOptions::NO_TICKET);
    // The server chooses the outbound suites: FIPS-approved only.
    crate::fips::tls::restrict(&mut builder)?;
    let anchors = X509::stack_from_pem(&std::fs::read(ca).context("read endpoint CA")?)?;
    ensure!(
        !anchors.is_empty(),
        "endpoint CA file contains no certificate"
    );
    let mut store = X509StoreBuilder::new()?;
    for anchor in anchors {
        store.add_cert(anchor)?;
    }
    // Replace the default verify paths: only the configured CA is trusted.
    builder.set_cert_store(store.build());
    builder.set_certificate_chain_file(certificate)?;
    builder.set_private_key_file(key, SslFiletype::PEM)?;
    builder.check_private_key()?;
    Ok(builder.build())
}

/// A message handed to the reversed channel; the reply is its outcome.
struct Job {
    request: Zeroizing<Vec<u8>>,
    operation: u32,
    reply: oneshot::Sender<std::result::Result<(), Failure>>,
}
/// The principal's open reversed channel, if any. The newest one wins: a
/// replaced channel sees its queue close and hands back at once.
struct Slot {
    version: Version,
    current: Mutex<Option<(u64, mpsc::Sender<Job>)>>,
    next: AtomicU64,
}
impl Slot {
    fn sender(&self) -> Option<mpsc::Sender<Job>> {
        self.current.lock().ok()?.as_ref().map(|(_, tx)| tx.clone())
    }
    fn register(&self, tx: mpsc::Sender<Job>) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut current) = self.current.lock() {
            *current = Some((id, tx));
        }
        id
    }
    fn unregister(&self, id: u64) {
        if let Ok(mut current) = self.current.lock()
            && current.as_ref().is_some_and(|(owner, _)| *owner == id)
        {
            *current = None;
        }
    }
}

/// Runs reversed channels for the configured principals.
#[derive(Clone)]
pub struct Reverse {
    slots: Arc<HashMap<String, Arc<Slot>>>,
    limits: Limits,
    report: Report,
}

/// Start one worker per endpoint on the current Tokio runtime. Returns the
/// engine's non-blocking sink (messages for unconfigured principals are
/// refused) and the handle with which connections serve reversed channels.
pub fn start(
    endpoints: HashMap<String, Endpoint>,
    limits: Limits,
    report: Report,
) -> (Sink, Reverse) {
    let mut senders = HashMap::new();
    let mut slots = HashMap::new();
    for (principal, endpoint) in endpoints {
        let (tx, rx) = mpsc::channel(limits.queue.max(1));
        let slot = Arc::new(Slot {
            version: endpoint.version,
            current: Mutex::new(None),
            next: AtomicU64::new(0),
        });
        tokio::spawn(worker(
            principal.clone(),
            Arc::new(endpoint),
            slot.clone(),
            rx,
            limits,
            report.clone(),
        ));
        senders.insert(principal.clone(), tx);
        slots.insert(principal, slot);
    }
    let sink: Sink = Box::new(move |message: Outbound| {
        senders
            .get(&message.endpoint)
            .is_some_and(|tx| tx.try_send(message).is_ok())
    });
    (
        sink,
        Reverse {
            slots: Arc::new(slots),
            limits,
            report,
        },
    )
}

#[derive(Debug)]
pub enum Failure {
    /// Transport failure: retried.
    Transient(String),
    /// The client answered and refused, or nothing can be sent: final.
    Final(String),
    /// The peer sent something other than the expected response, so the
    /// channel's framing can no longer be trusted: final for the message,
    /// and a reversed channel is closed.
    Broken(String),
}
impl Failure {
    fn message(&self) -> String {
        match self {
            Self::Transient(m) | Self::Final(m) | Self::Broken(m) => m.clone(),
        }
    }
}
fn broken(e: anyhow::Error) -> Failure {
    Failure::Broken(format!("{e:#}"))
}
/// A Response Message for `operation` with Result Status Success.
fn succeeded(
    response: &Node,
    version: Version,
    operation: u32,
) -> std::result::Result<Option<Node>, Failure> {
    match answer(response, version, operation).map_err(broken)? {
        Answer::Success(payload) => Ok(payload),
        Answer::Failed { status, reason } => Err(Failure::Final(format!(
            "client returned result status {status}, reason {reason:#x}"
        ))),
    }
}
async fn worker(
    principal: String,
    endpoint: Arc<Endpoint>,
    slot: Arc<Slot>,
    mut rx: mpsc::Receiver<Outbound>,
    limits: Limits,
    report: Report,
) {
    // What the client said about itself on the current dial-out session.
    let mut capabilities: Option<Capabilities> = None;
    while let Some(message) = rx.recv().await {
        let bytes = Zeroizing::new(message.message.encode());
        let mut outcome = Err("no delivery attempt".to_owned());
        for attempt in 0..limits.attempts.max(1) {
            if attempt > 0 {
                tokio::time::sleep(limits.backoff.saturating_mul(1 << (attempt - 1).min(6))).await;
            }
            let result = if let Some(tx) = slot.sender() {
                reversed(tx, &bytes, message.operation, limits).await
            } else if let Some(dial) = &endpoint.dial {
                let result = dial_out(
                    &principal,
                    &endpoint,
                    dial,
                    &mut capabilities,
                    &bytes,
                    message.operation,
                    limits,
                    &report,
                )
                .await;
                if result.is_err() {
                    capabilities = None;
                }
                result
            } else {
                Err(Failure::Final(
                    "no reversed channel is open and no dial-out address is configured".into(),
                ))
            };
            match result {
                Ok(()) => {
                    outcome = Ok(());
                    break;
                }
                Err(Failure::Final(error) | Failure::Broken(error)) => {
                    outcome = Err(error);
                    break;
                }
                Err(Failure::Transient(error)) => outcome = Err(error),
            }
        }
        drop(bytes);
        report(Delivered {
            owner: message.owner,
            operation: message.operation,
            object: Some(message.object),
            outcome,
        });
    }
}
async fn reversed(
    tx: mpsc::Sender<Job>,
    request: &[u8],
    operation: u32,
    limits: Limits,
) -> std::result::Result<(), Failure> {
    let closed = || Failure::Transient("reversed channel closed".into());
    let (reply, answer) = oneshot::channel();
    let job = Job {
        request: Zeroizing::new(request.to_vec()),
        operation,
        reply,
    };
    timeout(limits.io_timeout, tx.send(job))
        .await
        .map_err(|_| closed())?
        .map_err(|_| closed())?;
    timeout(limits.io_timeout.saturating_mul(2), answer)
        .await
        .map_err(|_| Failure::Transient("reversed channel response timeout".into()))?
        .map_err(|_| closed())?
}
#[allow(clippy::too_many_arguments)]
async fn dial_out(
    principal: &str,
    endpoint: &Endpoint,
    dial: &Dial,
    capabilities: &mut Option<Capabilities>,
    request: &[u8],
    operation: u32,
    limits: Limits,
    report: &Report,
) -> std::result::Result<(), Failure> {
    match &dial.transport {
        Transport::Ttlv => {
            let mut stream = connect(dial, limits).await?;
            let result = exchange_on(
                &mut Ttlv(&mut stream),
                principal,
                endpoint.version,
                capabilities,
                request,
                operation,
                limits,
                report,
            )
            .await;
            let _ = timeout(Duration::from_secs(2), stream.shutdown()).await;
            result
        }
        Transport::Https { target } => {
            let mut session = Https {
                dial,
                target,
                limits,
                stream: None,
            };
            let result = exchange_on(
                &mut session,
                principal,
                endpoint.version,
                capabilities,
                request,
                operation,
                limits,
                report,
            )
            .await;
            if let Some(mut stream) = session.stream.take() {
                let _ = timeout(Duration::from_secs(2), stream.shutdown()).await;
            }
            result
        }
    }
}
/// A mutually authenticated TLS connection to the endpoint.
async fn connect(
    dial: &Dial,
    limits: Limits,
) -> std::result::Result<SslStream<TcpStream>, Failure> {
    async {
        let socket = timeout(limits.connect_timeout, TcpStream::connect(&dial.address))
            .await
            .context("connect timeout")??;
        socket.set_nodelay(true)?;
        let ssl = dial.connector.configure()?.into_ssl(&dial.server_name)?;
        let mut stream = SslStream::new(ssl, socket)?;
        timeout(limits.connect_timeout, Pin::new(&mut stream).connect())
            .await
            .context("TLS handshake timeout")??;
        Ok::<_, anyhow::Error>(stream)
    }
    .await
    .map_err(|e| Failure::Transient(format!("{e:#}")))
}
/// Probe a 2.x client once per session, then send the message.
#[allow(clippy::too_many_arguments)]
async fn exchange_on<E: Exchange>(
    wire: &mut E,
    principal: &str,
    version: Version,
    capabilities: &mut Option<Capabilities>,
    request: &[u8],
    operation: u32,
    limits: Limits,
    report: &Report,
) -> std::result::Result<(), Failure> {
    if version >= Version(2, 0) && capabilities.is_none() {
        *capabilities = Some(probe(wire, principal, version, limits, report).await?);
    }
    if let Some(c) = capabilities {
        c.permits(version, operation)?;
    }
    let response = wire.exchange(request, limits.io_timeout).await?;
    succeeded(&response, version, operation).map(drop)
}
/// One request and its response message, however the connection frames them.
trait Exchange {
    async fn exchange(
        &mut self,
        request: &[u8],
        io: Duration,
    ) -> std::result::Result<Node, Failure>;
}
/// Binary TTLV on a stream.
struct Ttlv<'a, S>(&'a mut S);
impl<S: AsyncRead + AsyncWrite + Unpin> Exchange for Ttlv<'_, S> {
    async fn exchange(
        &mut self,
        request: &[u8],
        io: Duration,
    ) -> std::result::Result<Node, Failure> {
        round_trip(self.0, request, io).await
    }
}
/// HTTPS: one POST per message on a persistent connection, reconnecting
/// when the endpoint closes it.
struct Https<'a> {
    dial: &'a Dial,
    target: &'a str,
    limits: Limits,
    stream: Option<SslStream<TcpStream>>,
}
impl Exchange for Https<'_> {
    async fn exchange(
        &mut self,
        request: &[u8],
        io: Duration,
    ) -> std::result::Result<Node, Failure> {
        let mut stream = match self.stream.take() {
            Some(stream) => stream,
            None => connect(self.dial, self.limits).await?,
        };
        let host = host_header(&self.dial.address, &self.dial.server_name);
        let (response, keep) = timeout(io, post(&mut stream, &host, self.target, request))
            .await
            .map_err(|_| Failure::Transient("response timeout".into()))??;
        if keep {
            self.stream = Some(stream);
        } else {
            let _ = timeout(Duration::from_secs(2), stream.shutdown()).await;
        }
        Ok(response)
    }
}
/// The Host header: the name the certificate must match, and the port unless
/// it is the HTTPS default.
fn host_header(address: &str, server_name: &str) -> String {
    let name = if server_name.contains(':') {
        format!("[{server_name}]")
    } else {
        server_name.to_owned()
    };
    match address.rsplit_once(':') {
        Some((_, port)) if port != "443" => format!("{name}:{port}"),
        _ => name,
    }
}
/// Longest response head accepted.
const MAX_HTTP_HEAD: usize = 16 * 1024;
/// The KMIP TTLV media type (Profiles 1.3-2.1 5.3.1/5.3.2).
const TTLV_MEDIA_TYPE: &str = "application/octet-stream";
/// Send one KMIP request as an HTTP/1.1 POST and read its response. Returns
/// the decoded Response Message and whether the connection stays open.
///
/// The request follows 5.3.1: POST to the configured target, Content-Type
/// "application/octet-stream" for TTLV, Content-Length, Cache-Control
/// "no-cache", and the binary TTLV message as the body. The response must be
/// what 5.3.2 has the endpoint send: status 200, the same Content-Type and a
/// Content-Length that frames exactly one TTLV message.
async fn post<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    target: &str,
    request: &[u8],
) -> std::result::Result<(Node, bool), Failure> {
    let transient = |e: std::io::Error| Failure::Transient(format!("{e:#}"));
    let head = format!(
        "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {TTLV_MEDIA_TYPE}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\n\r\n",
        request.len()
    );
    let mut message = Zeroizing::new(Vec::with_capacity(head.len() + request.len()));
    message.extend_from_slice(head.as_bytes());
    message.extend_from_slice(request);
    stream.write_all(&message).await.map_err(transient)?;
    stream.flush().await.map_err(transient)?;
    let mut buffer = Vec::new();
    let response = loop {
        let response = read_head(stream, &mut buffer).await?;
        // An interim 1xx response precedes the final one (RFC 9110 15.2).
        if !(100..200).contains(&response.status) {
            break response;
        }
    };
    if response.status != 200 {
        let message = format!("endpoint answered HTTP status {}", response.status);
        return Err(if response.status >= 500 {
            Failure::Transient(message)
        } else {
            Failure::Final(message)
        });
    }
    let broken = |m: &str| Failure::Broken(m.to_owned());
    if response.chunked {
        return Err(broken("chunked HTTP response; Content-Length is required"));
    }
    let length = response
        .length
        .ok_or_else(|| broken("HTTP response without Content-Length"))?;
    if !response
        .media_type
        .as_deref()
        .is_some_and(|t| t.eq_ignore_ascii_case(TTLV_MEDIA_TYPE))
    {
        return Err(broken(
            "HTTP response Content-Type is not application/octet-stream",
        ));
    }
    if !(8..=ttlv::MAX_FRAME).contains(&length) {
        return Err(broken("HTTP response body is not one TTLV message"));
    }
    if buffer.len() > length {
        return Err(broken("unexpected data after the HTTP response body"));
    }
    let mut body = Zeroizing::new(std::mem::take(&mut buffer));
    let start = body.len();
    body.resize(length, 0);
    stream
        .read_exact(&mut body[start..])
        .await
        .map_err(transient)?;
    let header: [u8; 8] = body[..8].try_into().expect("length checked");
    if ttlv::frame_length(&header).ok() != Some(length) {
        return Err(broken("HTTP response body is not one TTLV message"));
    }
    let node = ttlv::decode(&body).map_err(|e| Failure::Broken(format!("{e}")))?;
    Ok((node, response.keep_alive))
}
/// The parts of an HTTP response head that delivery uses.
struct ResponseHead {
    status: u16,
    length: Option<usize>,
    chunked: bool,
    media_type: Option<String>,
    keep_alive: bool,
}
/// Read one response head; bytes after it stay in `buffer`.
async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
) -> std::result::Result<ResponseHead, Failure> {
    let broken = |m: &str| Failure::Broken(m.to_owned());
    let end = loop {
        if let Some(i) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buffer.len() > MAX_HTTP_HEAD {
            return Err(broken("HTTP response head too long"));
        }
        let mut chunk = [0; 1024];
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| Failure::Transient(format!("{e:#}")))?;
        if n == 0 {
            return Err(Failure::Transient(
                "connection closed before an HTTP response".into(),
            ));
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buffer[..end].to_vec())
        .map_err(|_| broken("HTTP response head is not text"))?;
    buffer.drain(..end + 4);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let http11 = match version {
        "HTTP/1.1" => true,
        "HTTP/1.0" => false,
        _ => return Err(broken("not an HTTP/1.0 or HTTP/1.1 response")),
    };
    let status = parts
        .next()
        .filter(|code| code.len() == 3)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| broken("invalid HTTP status line"))?;
    let mut response = ResponseHead {
        status,
        length: None,
        chunked: false,
        media_type: None,
        keep_alive: http11,
    };
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| broken("invalid HTTP header line"))?;
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                let length = value
                    .parse::<usize>()
                    .ok()
                    .filter(|_| value.bytes().all(|b| b.is_ascii_digit()))
                    .ok_or_else(|| broken("invalid Content-Length"))?;
                if response.length.is_some_and(|l| l != length) {
                    return Err(broken("conflicting Content-Length headers"));
                }
                response.length = Some(length);
            }
            "transfer-encoding" => response.chunked = true,
            "content-type" => {
                response.media_type = Some(
                    value
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_owned(),
                );
            }
            "connection" => {
                for token in value.split(',').map(str::trim) {
                    if token.eq_ignore_ascii_case("close") {
                        response.keep_alive = false;
                    } else if token.eq_ignore_ascii_case("keep-alive") && !http11 {
                        response.keep_alive = true;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(response)
}
/// Write one request and read one response message.
async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
    io: Duration,
) -> std::result::Result<Node, Failure> {
    let data = timeout(io, async {
        stream.write_all(request).await?;
        let mut header = [0; 8];
        stream.read_exact(&mut header).await?;
        let len = ttlv::frame_length(&header)?;
        let mut data = Zeroizing::new(vec![0; len]);
        data[..8].copy_from_slice(&header);
        stream.read_exact(&mut data[8..]).await?;
        Ok::<_, anyhow::Error>(data)
    })
    .await
    .context("response timeout")
    .and_then(|r| r)
    .map_err(|e| Failure::Transient(format!("{e:#}")))?;
    ttlv::decode(&data).map_err(|e| Failure::Broken(format!("{e}")))
}

/// A server-to-client request message (1.0 5.1/5.2; 2.1 section 6.2): the
/// request format with Protocol Version and Batch Count only.
fn request_message(v: Version, operation: u32, payload: Vec<Node>) -> Node {
    Node::structure(
        REQUEST_MESSAGE,
        vec![
            Node::structure(REQUEST_HEADER, vec![v.node(), Node::int(BATCH_COUNT, 1)]),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, operation),
                    Node::structure(REQUEST_PAYLOAD, payload),
                ],
            ),
        ],
    )
}
/// The client's answer to one request.
enum Answer {
    Success(Option<Node>),
    Failed { status: u32, reason: u32 },
}
fn answer(response: &Node, version: Version, operation: u32) -> Result<Answer> {
    ensure!(response.tag == RESPONSE_MESSAGE, "not a Response Message");
    let header = response.required(RESPONSE_HEADER)?;
    let v = header.required(PROTOCOL_VERSION)?;
    ensure!(
        v.required(PROTOCOL_VERSION_MAJOR)?.number()? == version.0
            && v.required(PROTOCOL_VERSION_MINOR)?.number()? == version.1,
        "response protocol version differs"
    );
    let items = response.all(BATCH_ITEM).collect::<Vec<_>>();
    ensure!(items.len() == 1, "response must contain one batch item");
    if let Some(op) = items[0].get(OPERATION) {
        ensure!(op.number()? == operation, "response operation differs");
    }
    let status = items[0].required(RESULT_STATUS)?.number()?;
    if status != 0 {
        let reason = items[0]
            .get(RESULT_REASON)
            .and_then(|n| n.number().ok())
            .unwrap_or(0);
        return Ok(Answer::Failed { status, reason });
    }
    Ok(Answer::Success(items[0].get(RESPONSE_PAYLOAD).cloned()))
}
/// The client's answer: a Response Message in the request's version with one
/// successful batch item for the same operation and no payload requirement.
pub fn check_response(response: &Node, version: Version, operation: u32) -> Result<()> {
    match answer(response, version, operation)? {
        Answer::Success(_) => Ok(()),
        Answer::Failed { status, reason } => {
            bail!("client returned result status {status}, reason {reason:#x}")
        }
    }
}

/// What a 2.x client reported about itself. None: it did not say (the probe
/// answered Operation Not Supported).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub versions: Option<Vec<Version>>,
    pub operations: Option<Vec<u32>>,
}
impl Capabilities {
    fn permits(&self, version: Version, operation: u32) -> std::result::Result<(), Failure> {
        if self
            .versions
            .as_ref()
            .is_some_and(|v| !v.contains(&version))
        {
            return Err(Failure::Final(format!(
                "client does not support protocol {}.{}",
                version.0, version.1
            )));
        }
        if self
            .operations
            .as_ref()
            .is_some_and(|ops| !ops.contains(&operation))
        {
            return Err(Failure::Final(format!(
                "client does not support operation {operation}"
            )));
        }
        Ok(())
    }
}
/// The versions this server offers in a server-to-client Discover Versions,
/// "ranked in decreasing order of preference" (2.1 section 6.2.1): the
/// endpoint version first, then the other final editions, newest first.
pub fn offered_versions(version: Version) -> Vec<Version> {
    let mut offered = vec![version];
    offered.extend(
        Version::supported(false)
            .into_iter()
            .filter(|v| *v != version),
    );
    offered
}
fn read_version(n: &Node) -> Result<Version> {
    ensure!(
        n.children()?
            .iter()
            .all(|f| { f.tag == PROTOCOL_VERSION_MAJOR || f.tag == PROTOCOL_VERSION_MINOR }),
        "unexpected Protocol Version field"
    );
    Ok(Version(
        n.required(PROTOCOL_VERSION_MAJOR)?.number()?,
        n.required(PROTOCOL_VERSION_MINOR)?.number()?,
    ))
}
/// Validate a Discover Versions response payload against the offer. The
/// client "SHALL return only the protocol versions that are supported by both
/// the client and server" (2.1 section 6.2.1), so anything outside the offer
/// makes the answer unusable.
pub fn discovered_versions(payload: Option<&Node>, offered: &[Version]) -> Result<Vec<Version>> {
    let Some(payload) = payload else {
        return Ok(vec![]);
    };
    let mut versions = vec![];
    for field in payload.children()? {
        ensure!(
            field.tag == PROTOCOL_VERSION,
            "unexpected Discover Versions field"
        );
        let v = read_version(field)?;
        ensure!(
            offered.contains(&v),
            "client returned protocol {}.{}, which the server did not offer",
            v.0,
            v.1
        );
        ensure!(!versions.contains(&v), "client repeated a protocol version");
        versions.push(v);
    }
    Ok(versions)
}
/// Validate a Query Operations response payload.
pub fn queried_operations(payload: Option<&Node>) -> Result<Vec<u32>> {
    let Some(payload) = payload else {
        return Ok(vec![]);
    };
    let mut operations = vec![];
    for field in payload.children()? {
        // Other Query results are allowed in a response but not asked for.
        if field.tag == OPERATION {
            let Value::Enumeration(op) = field.value else {
                bail!("Operation must be an enumeration");
            };
            operations.push(op);
        }
    }
    Ok(operations)
}
/// Discover Versions, then Query Operations, on one session. Each outcome is
/// reported (operation 30 or 24, no object). A transport failure ends the
/// session; an answer that does not follow the text is final.
async fn probe<E: Exchange>(
    wire: &mut E,
    principal: &str,
    version: Version,
    limits: Limits,
    report: &Report,
) -> std::result::Result<Capabilities, Failure> {
    let offered = offered_versions(version);
    let outcome = async {
        // REQ:84d6ba52cfd06ec5 the offered versions are ranked by preference
        let request = request_message(
            version,
            DISCOVER_VERSIONS,
            offered.iter().map(|v| v.node()).collect(),
        );
        let response = wire.exchange(&request.encode(), limits.io_timeout).await?;
        match answer(&response, version, DISCOVER_VERSIONS).map_err(broken)? {
            Answer::Success(payload) => discovered_versions(payload.as_ref(), &offered)
                .map(Some)
                .map_err(final_error),
            Answer::Failed { reason, .. } if reason == OPERATION_NOT_SUPPORTED => Ok(None),
            Answer::Failed { status, reason } => Err(Failure::Final(format!(
                "Discover Versions returned result status {status}, reason {reason:#x}"
            ))),
        }
    }
    .await;
    reported(report, principal, DISCOVER_VERSIONS, &outcome);
    let versions = outcome?;
    let outcome = async {
        // REQ:4546b8e550e099b8 the request names one Query Function
        let request = request_message(
            version,
            QUERY,
            vec![Node::enumeration(QUERY_FUNCTION, QUERY_OPERATIONS)],
        );
        let response = wire.exchange(&request.encode(), limits.io_timeout).await?;
        match answer(&response, version, QUERY).map_err(broken)? {
            Answer::Success(payload) => queried_operations(payload.as_ref())
                .map(Some)
                .map_err(final_error),
            Answer::Failed { reason, .. } if reason == OPERATION_NOT_SUPPORTED => Ok(None),
            Answer::Failed { status, reason } => Err(Failure::Final(format!(
                "Query returned result status {status}, reason {reason:#x}"
            ))),
        }
    }
    .await;
    reported(report, principal, QUERY, &outcome);
    Ok(Capabilities {
        versions,
        operations: outcome?,
    })
}
fn final_error(e: anyhow::Error) -> Failure {
    Failure::Final(format!("{e:#}"))
}
fn reported<T>(
    report: &Report,
    principal: &str,
    operation: u32,
    outcome: &std::result::Result<T, Failure>,
) {
    report(Delivered {
        owner: principal.to_owned(),
        operation,
        object: None,
        outcome: outcome.as_ref().map(drop).map_err(Failure::message),
    });
}

impl Reverse {
    /// Whether `principal` has an endpoint whose messages a reversed channel
    /// may carry.
    pub fn configured(&self, principal: &str) -> bool {
        self.slots.contains_key(principal)
    }
    /// Act as the client on `stream`, whose peer just accepted the server
    /// role: probe it, carry the principal's messages until the channel is
    /// idle, replaced or held too long, then hand the roles back with Set
    /// Endpoint Role (Endpoint Role Client, "the endpoint role for the client
    /// to apply", 2.1 table 349). Ok means the peer is the client again and
    /// the connection continues normally; any error closes it.
    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        principal: &str,
        stream: &mut S,
    ) -> Result<()> {
        let slot = self
            .slots
            .get(principal)
            .context("principal has no client endpoint")?;
        let (version, limits) = (slot.version, self.limits);
        let deadline = Instant::now() + limits.reverse_hold;
        // Open for messages at once; they wait in this queue for the probes.
        let (tx, mut rx) = mpsc::channel(1);
        let id = slot.register(tx);
        let capabilities = match probe(
            &mut Ttlv(&mut *stream),
            principal,
            version,
            limits,
            &self.report,
        )
        .await
        {
            Ok(capabilities) => Some(capabilities),
            // The client answered, but nothing can be sent: hand back.
            Err(Failure::Final(_)) => None,
            Err(Failure::Transient(error) | Failure::Broken(error)) => {
                slot.unregister(id);
                bail!("reversed channel failed: {error}")
            }
        };
        if let Some(capabilities) = capabilities {
            let carried = async {
                loop {
                    let job = tokio::select! {
                        job = rx.recv() => job,
                        _ = tokio::time::sleep(limits.reverse_idle) => None,
                        _ = tokio::time::sleep_until(deadline) => None,
                    };
                    let Some(job) = job else {
                        return Ok(());
                    };
                    let result = match capabilities.permits(version, job.operation) {
                        Err(e) => Err(e),
                        Ok(()) => round_trip(stream, &job.request, limits.io_timeout)
                            .await
                            .and_then(|response| {
                                succeeded(&response, version, job.operation).map(drop)
                            }),
                    };
                    let transport = match &result {
                        Err(Failure::Transient(error) | Failure::Broken(error)) => {
                            Some(error.clone())
                        }
                        _ => None,
                    };
                    let _ = job.reply.send(result);
                    if let Some(error) = transport {
                        bail!("reversed channel failed: {error}");
                    }
                }
            }
            .await;
            slot.unregister(id);
            carried?;
        }
        slot.unregister(id);
        // Jobs still queued here are dropped; their workers retry them.
        drop(rx);
        let outcome = async {
            let request = request_message(
                version,
                SET_ENDPOINT_ROLE,
                vec![Node::enumeration(ENDPOINT_ROLE, ROLE_CLIENT)],
            );
            let response = round_trip(stream, &request.encode(), limits.io_timeout).await?;
            match answer(&response, version, SET_ENDPOINT_ROLE).map_err(broken)? {
                // Table 350: "The accepted endpoint role as applied by the client."
                Answer::Success(Some(payload))
                    if payload.get(ENDPOINT_ROLE).and_then(|n| n.number().ok())
                        == Some(ROLE_CLIENT) =>
                {
                    Ok(())
                }
                Answer::Success(_) => Err(Failure::Final(
                    "client did not accept the client role".into(),
                )),
                Answer::Failed { status, reason } => Err(Failure::Final(format!(
                    "Set Endpoint Role returned result status {status}, reason {reason:#x}"
                ))),
            }
        }
        .await;
        reported(&self.report, principal, SET_ENDPOINT_ROLE, &outcome);
        outcome.map_err(|e| anyhow::anyhow!("roles not handed back: {}", e.message()))
    }
}
