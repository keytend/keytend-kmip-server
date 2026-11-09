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

//! Reserve capacity before accept: overload waits in the bounded kernel backlog,
//! with one admission future shared by both TLS listeners and no socket-drop loop.
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Instant,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};

/// Listener label values, indexed by `Accepted::https`.
pub(super) const LISTENERS: [&str; 2] = ["ttlv", "https"];

/// Coarse TLS handshake failure reasons (`tls_failure_reason`), plus the
/// 10 s handshake deadline. A handshake dropped at shutdown is written as
/// reason `cancelled`.
pub(super) const TLS_FAILURE_REASONS: [&str; 9] = [
    "no_client_certificate",
    "certificate_rejected",
    "peer_alert",
    "protocol_version",
    "no_shared_parameters",
    "not_tls",
    "connection_closed",
    "other",
    "timeout",
];
const TLS_TIMEOUT: usize = 8;

/// Classify a failed server handshake from OpenSSL's reason strings. Only a
/// fixed label leaves this function; the peer's data never does.
pub(super) fn tls_failure_reason(error: &openssl::ssl::Error) -> usize {
    use openssl::ssl::ErrorCode;
    let reasons: Vec<String> = error
        .ssl_error()
        .map(|stack| {
            stack
                .errors()
                .iter()
                .filter_map(|e| e.reason().map(str::to_ascii_lowercase))
                .collect()
        })
        .unwrap_or_default();
    let any = |needles: &[&str]| {
        reasons
            .iter()
            .any(|r| needles.iter().any(|needle| r.contains(needle)))
    };
    if any(&["peer did not return a certificate", "certificate required"]) {
        0
    } else if any(&["certificate verify failed", "certificate expired"]) {
        1
    } else if any(&["alert"]) {
        2
    } else if any(&[
        "unsupported protocol",
        "version too low",
        "version too high",
        "inappropriate fallback",
    ]) {
        3
    } else if any(&[
        "no shared cipher",
        "no suitable signature algorithm",
        "no shared signature algorithms",
        "no shared groups",
        "no suitable key share",
        "no suitable digest",
        "no ciphers available",
    ]) {
        4
    } else if any(&[
        "http request",
        "https proxy request",
        "wrong version number",
    ]) {
        5
    } else if any(&["unexpected eof"])
        || error.io_error().is_some()
        || (error.code() == ErrorCode::SYSCALL && reasons.is_empty())
        || error.code() == ErrorCode::ZERO_RETURN
    {
        6
    } else {
        7
    }
}

/// Counters of one listener.
#[derive(Default)]
struct Listener {
    accepted_total: AtomicU64,
    active: AtomicU64,
    closed_total: AtomicU64,
    clean_total: AtomicU64,
    error_total: AtomicU64,
    lifetime_timeout_total: AtomicU64,
    cancelled_total: AtomicU64,
    tls_started_total: AtomicU64,
    tls_succeeded_total: AtomicU64,
    tls_failed_total: [AtomicU64; TLS_FAILURE_REASONS.len()],
    tls_cancelled_total: AtomicU64,
    idle_timeout_total: AtomicU64,
    unlisted_total: AtomicU64,
}

#[derive(Default)]
pub(super) struct Metrics {
    capacity: u32,
    listeners: [Listener; 2],
    accept_error_total: AtomicU64,
    peak_active: AtomicU64,
    ttlv_responses_total: AtomicU64,
    admission_wait_total: AtomicU64,
    admission_waiting: AtomicU64,
    admission_wait_ns_total: AtomicU64,
}
impl Metrics {
    pub(super) fn new(capacity: u32) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }
    fn sum(&self, field: impl Fn(&Listener) -> &AtomicU64) -> u64 {
        self.listeners.iter().map(|l| field(l).load(Relaxed)).sum()
    }
    // Independent relaxed reads, not a transaction. Reconcile totals only after
    // quiescence. No principal, certificate, key, peer or request data is exposed.
    pub(super) fn snapshot(&self) -> serde_json::Value {
        let tls_failed: u64 = self
            .listeners
            .iter()
            .flat_map(|l| l.tls_failed_total[..TLS_TIMEOUT].iter())
            .map(|c| c.load(Relaxed))
            .sum();
        serde_json::json!({
            "tcp_accepted_total": self.sum(|l| &l.accepted_total),
            "ttlv_accepted_total": self.listeners[0].accepted_total.load(Relaxed),
            "https_accepted_total": self.listeners[1].accepted_total.load(Relaxed),
            "accept_error_total": self.accept_error_total.load(Relaxed),
            "active": self.sum(|l| &l.active),
            "peak_active": self.peak_active.load(Relaxed),
            "closed_total": self.sum(|l| &l.closed_total),
            "clean_total": self.sum(|l| &l.clean_total),
            "error_total": self.sum(|l| &l.error_total),
            "lifetime_timeout_total": self.sum(|l| &l.lifetime_timeout_total),
            "cancelled_total": self.sum(|l| &l.cancelled_total),
            "tls_started_total": self.sum(|l| &l.tls_started_total),
            "tls_succeeded_total": self.sum(|l| &l.tls_succeeded_total),
            "tls_failed_total": tls_failed,
            "tls_timeout_total": self.sum(|l| &l.tls_failed_total[TLS_TIMEOUT]),
            "tls_cancelled_total": self.sum(|l| &l.tls_cancelled_total),
            "idle_timeout_total": self.sum(|l| &l.idle_timeout_total),
            "ttlv_responses_total": self.ttlv_responses_total.load(Relaxed),
            "admission_wait_total": self.admission_wait_total.load(Relaxed),
            "admission_waiting": self.admission_waiting.load(Relaxed),
            "admission_wait_ns_total": self.admission_wait_ns_total.load(Relaxed),
            "max_connections": self.capacity,
        })
    }
    /// The connection families of `/metrics` (docs/metrics.md).
    pub(super) fn write_prometheus(&self, out: &mut keytend_kmip_server::metrics::Exposition) {
        let per_listener = |out: &mut keytend_kmip_server::metrics::Exposition,
                            name: &str,
                            help: &str,
                            kind: &str,
                            field: &dyn Fn(&Listener) -> &AtomicU64| {
            out.family(name, help, kind);
            for (listener, counters) in LISTENERS.iter().zip(&self.listeners) {
                out.sample(
                    name,
                    &[("listener", listener)],
                    field(counters).load(Relaxed) as f64,
                );
            }
        };
        per_listener(
            out,
            "kmip_connections_accepted_total",
            "TCP connections accepted, by listener (ttlv: binary TTLV; https: KMIP over HTTPS, whose per-request encoding is on kmip_requests_total).",
            "counter",
            &|l| &l.accepted_total,
        );
        per_listener(
            out,
            "kmip_connections_active",
            "Open connections, by listener.",
            "gauge",
            &|l| &l.active,
        );
        per_listener(
            out,
            "kmip_connections_closed_total",
            "Closed connections, by listener.",
            "counter",
            &|l| &l.closed_total,
        );
        per_listener(
            out,
            "kmip_connections_errored_total",
            "Connections that ended with an error (handshake failure, refused certificate, framing, timeout or I/O error), by listener.",
            "counter",
            &|l| &l.error_total,
        );
        per_listener(
            out,
            "kmip_connections_idle_closed_total",
            "Connections the server closed after --idle-timeout, by listener.",
            "counter",
            &|l| &l.idle_timeout_total,
        );
        per_listener(
            out,
            "kmip_connections_refused_unlisted_total",
            "Connections from a CA-valid certificate without a policy entry, answered with Permission Denied and closed, by listener.",
            "counter",
            &|l| &l.unlisted_total,
        );
        per_listener(
            out,
            "kmip_connections_cancelled_total",
            "Connections cancelled before they finished (shutdown drain), by listener.",
            "counter",
            &|l| &l.cancelled_total,
        );
        per_listener(
            out,
            "kmip_tls_handshakes_total",
            "TLS handshakes started, by listener.",
            "counter",
            &|l| &l.tls_started_total,
        );
        per_listener(
            out,
            "kmip_tls_handshakes_succeeded_total",
            "TLS handshakes completed, by listener.",
            "counter",
            &|l| &l.tls_succeeded_total,
        );
        out.family(
            "kmip_tls_handshake_failures_total",
            "Failed TLS handshakes, by listener and coarse reason.",
            "counter",
        );
        for (listener, counters) in LISTENERS.iter().zip(&self.listeners) {
            for (reason, counter) in TLS_FAILURE_REASONS.iter().zip(&counters.tls_failed_total) {
                out.sample(
                    "kmip_tls_handshake_failures_total",
                    &[("listener", listener), ("reason", reason)],
                    counter.load(Relaxed) as f64,
                );
            }
            out.sample(
                "kmip_tls_handshake_failures_total",
                &[("listener", listener), ("reason", "cancelled")],
                counters.tls_cancelled_total.load(Relaxed) as f64,
            );
        }
        let single = |out: &mut keytend_kmip_server::metrics::Exposition,
                      name: &str,
                      help: &str,
                      kind: &str,
                      value: f64| {
            out.family(name, help, kind);
            out.sample(name, &[], value);
        };
        single(
            out,
            "kmip_connections_accept_errors_total",
            "accept() failures on the KMIP listeners.",
            "counter",
            self.accept_error_total.load(Relaxed) as f64,
        );
        single(
            out,
            "kmip_connections_max",
            "Connection limit (--max-connections), shared by both KMIP listeners.",
            "gauge",
            self.capacity as f64,
        );
        single(
            out,
            "kmip_connections_peak_active",
            "Most connections open at once since start.",
            "gauge",
            self.peak_active.load(Relaxed) as f64,
        );
        single(
            out,
            "kmip_connection_admission_waits_total",
            "Times the accept loop waited for a free connection slot.",
            "counter",
            self.admission_wait_total.load(Relaxed) as f64,
        );
        single(
            out,
            "kmip_connection_admission_waiting",
            "Whether the accept loop is waiting for a free connection slot now.",
            "gauge",
            self.admission_waiting.load(Relaxed) as f64,
        );
        single(
            out,
            "kmip_connection_admission_wait_seconds_total",
            "Total time the accept loop waited for a free connection slot.",
            "counter",
            self.admission_wait_ns_total.load(Relaxed) as f64 / 1e9,
        );
    }
}

struct Wait<'a> {
    metrics: &'a Metrics,
    since: Instant,
}
impl<'a> Wait<'a> {
    fn new(metrics: &'a Metrics) -> Self {
        metrics.admission_wait_total.fetch_add(1, Relaxed);
        metrics.admission_waiting.fetch_add(1, Relaxed);
        Self {
            metrics,
            since: Instant::now(),
        }
    }
}
impl Drop for Wait<'_> {
    fn drop(&mut self) {
        self.metrics.admission_wait_ns_total.fetch_add(
            self.since.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            Relaxed,
        );
        self.metrics.admission_waiting.fetch_sub(1, Relaxed);
    }
}

pub(super) struct Accepted {
    pub socket: TcpStream,
    pub https: bool,
    pub lifecycle: Lifecycle,
}

pub(super) async fn accept(
    listener: &TcpListener,
    https_listener: Option<&TcpListener>,
    limit: Arc<Semaphore>,
    metrics: Arc<Metrics>,
) -> std::io::Result<Accepted> {
    let permit = match limit.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let _wait = Wait::new(&metrics);
            limit
                .acquire_owned()
                .await
                .expect("admission semaphore is never closed")
        }
    };
    let (result, https) = tokio::select! {
        result = listener.accept() => (result, false),
        result = async { match https_listener {
            Some(listener) => listener.accept().await,
            None => std::future::pending().await,
        }} => (result, true),
    };
    let (socket, _peer) = result.inspect_err(|_| {
        metrics.accept_error_total.fetch_add(1, Relaxed);
    })?;
    let listener = &metrics.listeners[usize::from(https)];
    listener.accepted_total.fetch_add(1, Relaxed);
    listener.active.fetch_add(1, Relaxed);
    let active = metrics.sum(|l| &l.active);
    metrics.peak_active.fetch_max(active, Relaxed);
    Ok(Accepted {
        socket,
        https,
        lifecycle: Lifecycle {
            metrics,
            listener: usize::from(https),
            _permit: permit,
            finished: false,
            handshaking: false,
        },
    })
}

/// Keep capacity and accounting attached even to a task cancelled before polling.
/// No per-refusal logging or unbounded user-space waiting tasks are created.
pub(super) struct Lifecycle {
    metrics: Arc<Metrics>,
    /// Index into `Metrics::listeners`.
    listener: usize,
    _permit: OwnedSemaphorePermit,
    finished: bool,
    handshaking: bool,
}
impl Lifecycle {
    fn counters(&self) -> &Listener {
        &self.metrics.listeners[self.listener]
    }
    pub(super) fn tls_started(&mut self) {
        self.handshaking = true;
        self.counters().tls_started_total.fetch_add(1, Relaxed);
    }
    /// `failure`: None for success, else an index into `TLS_FAILURE_REASONS`.
    pub(super) fn tls_finished(&mut self, failure: Option<usize>) {
        self.handshaking = false;
        let counters = self.counters();
        match failure {
            None => &counters.tls_succeeded_total,
            Some(reason) => &counters.tls_failed_total[reason.min(TLS_FAILURE_REASONS.len() - 1)],
        }
        .fetch_add(1, Relaxed);
    }
    pub(super) fn tls_timed_out(&mut self) {
        self.tls_finished(Some(TLS_TIMEOUT));
    }
    pub(super) fn idle_timeout(&self) {
        self.counters().idle_timeout_total.fetch_add(1, Relaxed);
    }
    pub(super) fn unlisted(&self) {
        self.counters().unlisted_total.fetch_add(1, Relaxed);
    }
    pub(super) fn response_written(&self) {
        self.metrics.ttlv_responses_total.fetch_add(1, Relaxed);
    }
    pub(super) fn finish(&mut self, error: bool, lifetime_timeout: bool) {
        self.finished = true;
        let counters = self.counters();
        if !error && !lifetime_timeout {
            counters.clean_total.fetch_add(1, Relaxed);
        }
        if error {
            counters.error_total.fetch_add(1, Relaxed);
        }
        if lifetime_timeout {
            counters.lifetime_timeout_total.fetch_add(1, Relaxed);
        }
    }
}
impl Drop for Lifecycle {
    fn drop(&mut self) {
        let counters = self.counters();
        if self.handshaking {
            counters.tls_cancelled_total.fetch_add(1, Relaxed);
        }
        if !self.finished {
            counters.cancelled_total.fetch_add(1, Relaxed);
        }
        counters.active.fetch_sub(1, Relaxed);
        counters.closed_total.fetch_add(1, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancelling_a_saturated_accept_releases_wait_accounting_and_connection_capacity() {
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let address = listener.local_addr().unwrap();
        let limit = Arc::new(Semaphore::new(1));
        let metrics = Arc::new(Metrics::new(1));
        let _client = TcpStream::connect(address).await.unwrap();
        let first = accept(&listener, None, limit.clone(), metrics.clone())
            .await
            .unwrap();
        let waiter = {
            let listener = listener.clone();
            let limit = limit.clone();
            let metrics = metrics.clone();
            tokio::spawn(async move { accept(&listener, None, limit, metrics).await })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while metrics.admission_waiting.load(Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        waiter.abort();
        assert!(matches!(waiter.await, Err(error) if error.is_cancelled()));
        assert_eq!(metrics.admission_waiting.load(Relaxed), 0);
        assert_eq!(metrics.admission_wait_total.load(Relaxed), 1);
        drop(first);
        assert_eq!(limit.available_permits(), 1);
        assert_eq!(metrics.sum(|l| &l.active), 0);
        assert_eq!(metrics.sum(|l| &l.closed_total), 1);
        assert_eq!(metrics.sum(|l| &l.cancelled_total), 1);
        let _client2 = TcpStream::connect(address).await.unwrap();
        let mut second = accept(&listener, None, limit.clone(), metrics.clone())
            .await
            .unwrap();
        second.lifecycle.tls_started();
        drop(second);
        assert_eq!(metrics.sum(|l| &l.tls_cancelled_total), 1);
        assert_eq!(limit.available_permits(), 1);
    }
}
