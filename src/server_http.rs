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

//! Bounded KMIP HTTP/1.0 and HTTP/1.1 over the authenticated TLS listener.
use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode, Version as HttpVersion, body::Incoming, header,
    server::conn::http1, service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use keytend_kmip_server::{
    encoding::{Format, MAX_TEXT_FRAME, TextEncoding},
    tags::*,
};
use std::{
    convert::Infallible,
    io,
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::OwnedSemaphorePermit,
    time::{Instant, Sleep},
};
use zeroize::Zeroize;
#[derive(Clone)]
pub(super) struct Config {
    path: Arc<str>,
    requests: Arc<Semaphore>,
    forms: TextEncoding,
    idle: Option<Duration>,
}
impl Config {
    pub(super) fn new(path: String, forms: TextEncoding, idle: Option<Duration>) -> Self {
        Self {
            path: Arc::from(path),
            requests: Arc::new(Semaphore::new(4)),
            forms,
            idle,
        }
    }
}
/// Request headers, and each stalled write, must finish within this time.
const IO_DEADLINE: Duration = Duration::from_secs(10);
/// Where a connection is between requests, for its read deadline.
#[derive(Clone, Copy)]
enum Phase {
    /// Waiting for a request since then: the idle limit applies.
    Idle(Instant),
    /// The first bytes of a request arrived then: the header deadline applies.
    Header(Instant),
    /// Headers complete; the handler bounds the body and the work.
    Busy,
}
/// hyper's own header timer starts as soon as a keep-alive connection waits
/// for its next request, so it would close idle connections after the header
/// deadline. This wrapper separates the idle limit (`--idle-timeout`, none
/// when 0) from the header deadline, which starts at a request's first byte.
struct Deadlines<S> {
    io: S,
    phase: Arc<std::sync::Mutex<Phase>>,
    idle: Option<Duration>,
    /// `IO_DEADLINE` outside tests.
    deadline: Duration,
    read_timer: Option<Pin<Box<Sleep>>>,
    write_timer: Option<Pin<Box<Sleep>>>,
}
impl<S> Deadlines<S> {
    fn new(io: S, phase: Arc<std::sync::Mutex<Phase>>, idle: Option<Duration>) -> Self {
        Self {
            io,
            phase,
            idle,
            deadline: IO_DEADLINE,
            read_timer: None,
            write_timer: None,
        }
    }
}
fn set_phase(phase: &std::sync::Mutex<Phase>, value: Phase) {
    *phase.lock().unwrap_or_else(|e| e.into_inner()) = value;
}
fn expired(
    timer: &mut Option<Pin<Box<Sleep>>>,
    deadline: Instant,
    cx: &mut TaskContext<'_>,
) -> bool {
    let timer = timer.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
    if timer.deadline() != deadline {
        timer.as_mut().reset(deadline);
    }
    timer.as_mut().poll(cx).is_ready()
}
impl<S: AsyncRead + Unpin> AsyncRead for Deadlines<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        match Pin::new(&mut this.io).poll_read(cx, buf) {
            Poll::Ready(result) => {
                this.read_timer = None;
                let mut phase = this.phase.lock().unwrap_or_else(|e| e.into_inner());
                if buf.filled().len() > before && matches!(*phase, Phase::Idle(_)) {
                    *phase = Phase::Header(Instant::now());
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                let phase = *this.phase.lock().unwrap_or_else(|e| e.into_inner());
                let deadline = match phase {
                    Phase::Idle(since) => this.idle.map(|limit| since + limit),
                    Phase::Header(since) => Some(since + this.deadline),
                    Phase::Busy => None,
                };
                match deadline {
                    Some(deadline) if expired(&mut this.read_timer, deadline, cx) => {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            match phase {
                                Phase::Idle(_) => "idle timeout",
                                _ => "request header timeout",
                            },
                        )))
                    }
                    Some(_) => Poll::Pending,
                    None => {
                        this.read_timer = None;
                        Poll::Pending
                    }
                }
            }
        }
    }
}
impl<S: AsyncWrite + Unpin> Deadlines<S> {
    /// A write, flush or shutdown that makes no progress for the deadline fails.
    fn bounded<T>(
        &mut self,
        cx: &mut TaskContext<'_>,
        op: impl FnOnce(Pin<&mut S>, &mut TaskContext<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        match op(Pin::new(&mut self.io), cx) {
            Poll::Ready(result) => {
                self.write_timer = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let deadline = self
                    .write_timer
                    .as_ref()
                    .map_or_else(|| Instant::now() + self.deadline, |t| t.deadline());
                if expired(&mut self.write_timer, deadline, cx) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "write timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Deadlines<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.bounded(cx, |io, cx| io.poll_write(cx, data))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.bounded(cx, |io, cx| io.poll_flush(cx))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.bounded(cx, |io, cx| io.poll_shutdown(cx))
    }
}
/// Whether a connection ended because its idle limit expired.
pub(super) fn idle_timed_out(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::TimedOut && e.to_string() == "idle timeout")
    })
}
/// Marks the connection busy while a request is handled, idle afterwards.
struct Busy(Arc<std::sync::Mutex<Phase>>);
impl Busy {
    fn new(phase: Arc<std::sync::Mutex<Phase>>) -> Self {
        set_phase(&phase, Phase::Busy);
        Self(phase)
    }
}
impl Drop for Busy {
    fn drop(&mut self) {
        set_phase(&self.0, Phase::Idle(Instant::now()));
    }
}
struct Payload {
    bytes: Zeroizing<Vec<u8>>,
    _permit: Option<OwnedSemaphorePermit>,
}
impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
type Reply = Response<Full<Bytes>>;
#[derive(Debug)]
struct HttpFailure(StatusCode);
impl std::fmt::Display for HttpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for HttpFailure {}
fn reply(
    status: StatusCode,
    version: HttpVersion,
    format: Option<Format>,
    bytes: Zeroizing<Vec<u8>>,
    permit: Option<OwnedSemaphorePermit>,
) -> Reply {
    // hyper keeps an HTTP/1.0 connection that asked for keep-alive (as in the
    // Profiles 5.3.3.1 informative wire encoding) only when the handler labels
    // its response HTTP/1.1: it then adds `Connection: keep-alive` and still
    // sends an HTTP/1.0 status line. A response labelled HTTP/1.0 disables
    // keep-alive. Error replies close the connection and keep the request
    // version, so hyper never appends keep-alive to their `close`.
    let mut response = Response::builder()
        .status(status)
        .version(if status == StatusCode::OK {
            HttpVersion::HTTP_11
        } else {
            version
        })
        .header(
            header::CONTENT_TYPE,
            format
                .map(Format::content_type)
                .unwrap_or("text/plain; charset=utf-8"),
        )
        .header(header::CONTENT_LENGTH, bytes.len())
        .header(header::CACHE_CONTROL, "no-cache");
    if status != StatusCode::OK {
        response = response.header(header::CONNECTION, "close")
    }
    if status == StatusCode::METHOD_NOT_ALLOWED {
        response = response.header(header::ALLOW, "POST")
    }
    response
        .body(Full::new(Bytes::from_owner(Payload {
            bytes,
            _permit: permit,
        })))
        .expect("fixed HTTP headers")
}
fn error(status: StatusCode, version: HttpVersion, permit: Option<OwnedSemaphorePermit>) -> Reply {
    reply(
        status,
        version,
        None,
        Zeroizing::new(
            status
                .canonical_reason()
                .unwrap_or("HTTP error")
                .as_bytes()
                .to_vec(),
        ),
        permit,
    )
}
fn content_type(value: &str) -> Option<Format> {
    let mut parts = value.split(';');
    let media = parts.next()?.trim();
    let format = if media.eq_ignore_ascii_case("application/octet-stream") {
        Format::Ttlv
    } else if media.eq_ignore_ascii_case("application/json") {
        Format::Json
    } else if media.eq_ignore_ascii_case("text/xml")
        || media.eq_ignore_ascii_case("application/xml")
    {
        Format::Xml
    } else {
        return None;
    };
    let mut charset = false;
    for part in parts {
        let (k, v) = part.trim().split_once('=')?;
        if k.eq_ignore_ascii_case("charset") {
            if charset || !v.trim().trim_matches('"').eq_ignore_ascii_case("utf-8") {
                return None;
            }
            charset = true;
        }
    }
    Some(format)
}
fn quality(s: &str) -> Option<u16> {
    let (whole, fraction) = s.split_once('.').unwrap_or((s, ""));
    if !["0", "1"].contains(&whole)
        || fraction.len() > 3
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || whole == "1" && fraction.bytes().any(|b| b != b'0')
    {
        return None;
    }
    let frac = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u16>().ok()? * 10u16.pow(3 - fraction.len() as u32)
    };
    Some(if whole == "1" { 1000 } else { frac })
}
fn accepted(headers: &hyper::HeaderMap, requested: Format) -> Option<Format> {
    if !headers.contains_key(header::ACCEPT) {
        return Some(requested);
    }
    let choices = [requested, Format::Ttlv, Format::Json, Format::Xml];
    let mut best = None;
    let mut best_quality = 0;
    for format in choices {
        let mut specificity = -1;
        let mut q = 0;
        for value in headers.get_all(header::ACCEPT) {
            for item in value.to_str().ok()?.split(',') {
                let mut parts = item.split(';');
                let media = parts.next()?.trim();
                let score = if media.eq_ignore_ascii_case(format.content_type())
                    || format == Format::Xml && media.eq_ignore_ascii_case("application/xml")
                {
                    2
                } else if media == "*/*" {
                    0
                } else if let Some(prefix) = media.strip_suffix("/*") {
                    if prefix.eq_ignore_ascii_case(format.content_type().split_once('/').unwrap().0)
                    {
                        1
                    } else {
                        -1
                    }
                } else {
                    -1
                };
                let mut weight = 1000;
                let mut weighted = false;
                for p in parts {
                    let (k, v) = p.trim().split_once('=')?;
                    if k.eq_ignore_ascii_case("q") {
                        if weighted {
                            return None;
                        }
                        weight = quality(v)?;
                        weighted = true;
                    }
                }
                if score > specificity {
                    specificity = score;
                    q = weight
                } else if score == specificity {
                    q = q.max(weight)
                }
            }
        }
        if specificity >= 0 && q > best_quality {
            best = Some(format);
            best_quality = q;
        }
    }
    best
}
/// Serve KMIP over HTTP on an authenticated TLS stream. `owner` is the policy
/// entry and the connection (for `Engine::with_channel`), or `None` for
/// a CA-valid certificate the server refuses (`refusal`): its first request
/// gets the same versioned answer as on the binary listener (`refuse` in
/// main.rs), Permission Denied when it has no policy entry and General
/// Failure when the store could not check it, with HTTP status 200 because a
/// KMIP response exists (Profiles 2.1 section 5.3), and the connection then
/// closes.
pub(super) async fn serve(
    stream: SslStream<TcpStream>,
    engine: Arc<Mutex<Engine>>,
    owner: Option<(Principal, Channel)>,
    cert: openssl::x509::X509,
    config: Config,
    refusal: Refusal,
) -> Result<()> {
    let phase = Arc::new(std::sync::Mutex::new(Phase::Idle(Instant::now())));
    // An unlisted peer has no session to keep open.
    let idle = if owner.is_some() {
        config.idle
    } else {
        Some(Duration::from_secs(30))
    };
    let io = Deadlines::new(stream, phase.clone(), idle);
    let service = service_fn(move |request| {
        let engine = engine.clone();
        let owner = owner.clone();
        let cert = cert.clone();
        let config = config.clone();
        let busy = Busy::new(phase.clone());
        async move {
            let reply = handle(request, engine, owner, cert, config, refusal).await;
            drop(busy);
            Ok::<_, Infallible>(reply)
        }
    });
    http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(None)
        .max_headers(64)
        .max_buf_size(16 * 1024)
        .serve_connection(TokioIo::new(io), service)
        .await?;
    Ok(())
}
async fn handle(
    mut request: Request<Incoming>,
    engine: Arc<Mutex<Engine>>,
    owner: Option<(Principal, Channel)>,
    cert: openssl::x509::X509,
    config: Config,
    refusal: Refusal,
) -> Reply {
    let version = request.version();
    if ![HttpVersion::HTTP_10, HttpVersion::HTTP_11].contains(&version) {
        return error(StatusCode::HTTP_VERSION_NOT_SUPPORTED, version, None);
    }
    if version == HttpVersion::HTTP_11
        && (request.headers().get_all(header::HOST).iter().count() != 1
            || request
                .headers()
                .get(header::HOST)
                .is_none_or(|v| v.as_bytes().is_empty()))
    {
        return error(StatusCode::BAD_REQUEST, version, None);
    }
    if request.method() != hyper::Method::POST {
        return error(StatusCode::METHOD_NOT_ALLOWED, version, None);
    }
    if request.uri().path() != config.path.as_ref() || request.uri().query().is_some() {
        return error(StatusCode::NOT_FOUND, version, None);
    }
    if request.headers().contains_key(header::TRANSFER_ENCODING)
        || request.headers().contains_key(header::TRAILER)
    {
        return error(StatusCode::BAD_REQUEST, version, None);
    }
    if request
        .headers()
        .get_all(header::CONTENT_LENGTH)
        .iter()
        .count()
        != 1
    {
        return error(StatusCode::LENGTH_REQUIRED, version, None);
    }
    let Some(length) = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<usize>().ok())
    else {
        return error(StatusCode::BAD_REQUEST, version, None);
    };
    if request
        .headers()
        .get_all(header::CONTENT_TYPE)
        .iter()
        .count()
        != 1
    {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, version, None);
    }
    let Some(input) = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(content_type)
    else {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, version, None);
    };
    if length
        > if input == Format::Ttlv {
            ttlv::MAX_FRAME
        } else {
            MAX_TEXT_FRAME
        }
    {
        return error(StatusCode::PAYLOAD_TOO_LARGE, version, None);
    }
    let Some(output) = accepted(request.headers(), input) else {
        return error(StatusCode::NOT_ACCEPTABLE, version, None);
    };
    let Ok(permit) = config.requests.clone().try_acquire_owned() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, version, None);
    };
    let body = timeout(Duration::from_secs(10), async {
        let mut bytes = Zeroizing::new(Vec::with_capacity(length));
        while let Some(frame) = request.body_mut().frame().await {
            let frame = frame?;
            let data = frame
                .into_data()
                .map_err(|_| anyhow::anyhow!("unexpected body trailers"))?;
            anyhow::ensure!(
                bytes.len().saturating_add(data.len()) <= length,
                "request body too large"
            );
            bytes.extend_from_slice(&data);
            if let Ok(mut data) = data.try_into_mut() {
                data.as_mut().zeroize()
            }
        }
        anyhow::ensure!(bytes.len() == length, "request body length mismatch");
        Ok::<_, anyhow::Error>(bytes)
    })
    .await;
    let body = match body {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => return error(StatusCode::BAD_REQUEST, version, Some(permit)),
        Err(_) => return error(StatusCode::REQUEST_TIMEOUT, version, Some(permit)),
    };
    let forms = config.forms;
    let unlisted = owner.is_none();
    let result = tokio::task::spawn_blocking(move || -> Result<Zeroizing<Vec<u8>>> {
        let request = match input.decode(&body) {
            Ok(request) => request,
            Err(_) => {
                return output.encode_with(
                    &error_response(Version(1, 4), Failure::new(4, "Malformed KMIP message")),
                    &forms,
                );
            }
        };
        // Echoed correlation must be representable even in an error response.
        if let Some(correlation) = request
            .get(REQUEST_HEADER)
            .and_then(|h| h.get(CLIENT_CORRELATION_VALUE))
        {
            output
                .encode_with(correlation, &forms)
                .map_err(|_| HttpFailure(StatusCode::NOT_ACCEPTABLE))?;
        }
        if cert
            .not_after()
            .compare(Asn1Time::days_from_now(0)?.as_ref())?
            .is_lt()
        {
            return Err(HttpFailure(StatusCode::FORBIDDEN).into());
        }
        let Some((owner, channel)) = owner else {
            if refusal == Refusal::StoreFailure {
                return output.encode_with(&store_failure_response(&request), &forms);
            }
            // No permitted operation, so no item reaches identifiers, objects,
            // credentials or the store: every item is Permission Denied.
            let response = engine
                .lock()
                .map_err(|_| anyhow::anyhow!("storage mutex poisoned"))?
                .process_with_grants_encoded(UNLISTED_OWNER, &request, Some(&[]), &[], output)
                .map_err(|f| {
                    if f.unanswerable() {
                        anyhow::Error::from(HttpFailure(StatusCode::BAD_REQUEST))
                    } else {
                        anyhow::anyhow!(f.message)
                    }
                })?;
            return output.encode_with(&response, &forms);
        };
        // Header-credential verifier derivations run without the engine lock.
        let work = engine
            .lock()
            .map_err(|_| anyhow::anyhow!("storage mutex poisoned"))?
            .credential_work(&owner.name, &request, Some(&owner.operations));
        let derivations = work.run();
        let mut engine = engine
            .lock()
            .map_err(|_| anyhow::anyhow!("storage mutex poisoned"))?;
        // Before commit, enforce the client limit on binary TTLV-equivalent bytes
        // and the independent frame limit on the selected encoder's bytes.
        let response = derivations
            .scope(|| {
                engine.with_channel(&channel, |engine| {
                    engine.process_with_grants_encoded(
                        &owner.name,
                        &request,
                        Some(&owner.operations),
                        &owner.object_grants,
                        output,
                    )
                })
            })
            .map_err(|f| {
                if f.unanswerable() {
                    // No conforming KMIP response fits; nothing was committed.
                    anyhow::Error::from(HttpFailure(StatusCode::BAD_REQUEST))
                } else {
                    anyhow::anyhow!(f.message)
                }
            })?;
        output.encode_with(&response, &forms)
    })
    .await;
    match result {
        Ok(Ok(bytes)) if unlisted => {
            let mut response = reply(StatusCode::OK, version, Some(output), bytes, Some(permit));
            response.headers_mut().insert(
                header::CONNECTION,
                header::HeaderValue::from_static("close"),
            );
            response
        }
        Ok(Ok(bytes)) => reply(StatusCode::OK, version, Some(output), bytes, Some(permit)),
        Ok(Err(failure)) => error(
            failure
                .downcast_ref::<HttpFailure>()
                .map(|f| f.0)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            version,
            Some(permit),
        ),
        _ => error(StatusCode::INTERNAL_SERVER_ERROR, version, Some(permit)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn timed(
        idle: Option<Duration>,
    ) -> (
        Deadlines<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
        Arc<std::sync::Mutex<Phase>>,
    ) {
        let (server, client) = tokio::io::duplex(64);
        let phase = Arc::new(std::sync::Mutex::new(Phase::Idle(Instant::now())));
        let mut io = Deadlines::new(server, phase.clone(), idle);
        io.deadline = Duration::from_millis(150);
        (io, client, phase)
    }
    async fn read_error(io: &mut Deadlines<tokio::io::DuplexStream>) -> io::Error {
        let mut buf = [0; 8];
        loop {
            match io.read(&mut buf).await {
                Err(e) => return e,
                Ok(0) => panic!("unexpected end of stream"),
                Ok(_) => continue,
            }
        }
    }
    #[tokio::test]
    async fn idle_limit_closes_a_waiting_connection_and_zero_never_does() {
        let (mut io, _client, _) = timed(Some(Duration::from_millis(100)));
        let started = std::time::Instant::now();
        let e = read_error(&mut io).await;
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert_eq!(e.to_string(), "idle timeout");
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(idle_timed_out(&anyhow::Error::from(e)));
        // `--idle-timeout 0`: still waiting long after both deadlines.
        let (mut io, _client, _) = timed(None);
        let mut buf = [0; 8];
        assert!(
            tokio::time::timeout(Duration::from_millis(400), io.read(&mut buf))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn header_deadline_starts_at_the_first_byte_even_without_an_idle_limit() {
        let (mut io, mut client, _) = timed(None);
        client.write_all(b"POST").await.unwrap();
        let mut buf = [0; 4];
        io.read_exact(&mut buf).await.unwrap();
        let e = read_error(&mut io).await;
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert_eq!(e.to_string(), "request header timeout");
    }
    #[tokio::test]
    async fn a_busy_connection_has_no_read_deadline_and_idles_again_afterwards() {
        let (mut io, mut client, phase) = timed(Some(Duration::from_millis(100)));
        client.write_all(b"POST").await.unwrap();
        let mut buf = [0; 4];
        io.read_exact(&mut buf).await.unwrap();
        let busy = Busy::new(phase.clone());
        assert!(
            tokio::time::timeout(Duration::from_millis(400), io.read(&mut buf))
                .await
                .is_err()
        );
        drop(busy);
        assert!(matches!(*phase.lock().unwrap(), Phase::Idle(_)));
        assert_eq!(read_error(&mut io).await.to_string(), "idle timeout");
    }
    #[tokio::test]
    async fn a_stalled_write_fails_after_the_deadline() {
        let (mut io, _client, _) = timed(None);
        let e = loop {
            if let Err(e) = io.write(&[0; 64]).await {
                break e;
            }
        };
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    }
    #[test]
    fn media_types_are_explicit_and_charsets_are_utf8() {
        assert!(content_type("Application/JSON; charset=\"UTF-8\"") == Some(Format::Json));
        assert!(content_type("text/xml") == Some(Format::Xml));
        assert!(content_type("application/octet-stream") == Some(Format::Ttlv));
        for value in [
            "text/plain",
            "application/json; charset=latin1",
            "application/json; charset=utf-8; charset=utf-8",
        ] {
            assert!(content_type(value).is_none());
        }
    }
    #[test]
    fn only_kmip_replies_let_hyper_keep_http10_connections() {
        let ok = reply(
            StatusCode::OK,
            HttpVersion::HTTP_10,
            Some(Format::Ttlv),
            Zeroizing::new(vec![]),
            None,
        );
        // hyper rewrites the status line to HTTP/1.0 and adds keep-alive.
        assert_eq!(ok.version(), HttpVersion::HTTP_11);
        assert!(ok.headers().get(header::CONNECTION).is_none());
        let failed = error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            HttpVersion::HTTP_10,
            None,
        );
        assert_eq!(failed.version(), HttpVersion::HTTP_10);
        assert_eq!(failed.headers()[header::CONNECTION], "close");
        assert_eq!(failed.headers()[header::CACHE_CONTROL], "no-cache");
    }
    #[test]
    fn accept_respects_specific_exclusions_wildcards_and_safe_defaults() {
        let mut h = hyper::HeaderMap::new();
        assert!(accepted(&h, Format::Xml) == Some(Format::Xml));
        h.insert(
            header::ACCEPT,
            "application/json;q=0, */*;q=1".parse().unwrap(),
        );
        assert!(accepted(&h, Format::Json) == Some(Format::Ttlv));
        h.insert(
            header::ACCEPT,
            "text/xml;q=0.5, application/json;q=0.9".parse().unwrap(),
        );
        assert!(accepted(&h, Format::Ttlv) == Some(Format::Json));
        h.insert(header::ACCEPT, "image/*".parse().unwrap());
        assert!(accepted(&h, Format::Json).is_none());
        for bad in [
            "application/json;q=2",
            "application/json;q=0.1234",
            "application/json;q=1.1",
        ] {
            h.insert(header::ACCEPT, bad.parse().unwrap());
            assert!(accepted(&h, Format::Json).is_none());
        }
    }
}
