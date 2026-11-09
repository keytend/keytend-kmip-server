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

//! `GET /metrics` on the health listener (docs/metrics.md): Prometheus text
//! format built from the engine's request registry, the connection counters,
//! build and FIPS information, store state and the periodic object census.
//! It is never served on the KMIP listeners.
use crate::network;
use keytend_kmip_server::{
    metrics::{Census, Exposition, Registry},
    protocol::Engine,
};
use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// `--metrics`: whether the health listener serves `/metrics`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(super) enum MetricsSetting {
    /// Serve `/metrics` (default).
    #[default]
    On,
    /// Answer `/metrics` with 404 and run no object census.
    Off,
}

/// `--metrics-object-census-interval` default, bounds and page size.
pub(super) const DEFAULT_CENSUS_INTERVAL: u64 = 300;
pub(super) const MIN_CENSUS_INTERVAL: u64 = 10;
pub(super) const MAX_CENSUS_INTERVAL: u64 = 86_400;
/// Records read per engine lock acquisition, so a census never holds the
/// engine for long.
const CENSUS_PAGE: usize = 256;

/// `0` (no census) or MIN..=MAX seconds.
pub(super) fn census_interval(text: &str) -> Result<u64, String> {
    let value: u64 = text.parse().map_err(|e| format!("{e}"))?;
    if value == 0 || (MIN_CENSUS_INTERVAL..=MAX_CENSUS_INTERVAL).contains(&value) {
        Ok(value)
    } else {
        Err(format!(
            "must be 0 (no census) or {MIN_CENSUS_INTERVAL}..={MAX_CENSUS_INTERVAL} seconds"
        ))
    }
}

fn unix(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

/// SHA-256 of the running executable, read in 64 KiB chunks.
fn executable_sha256() -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(std::env::current_exe().ok()?).ok()?;
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256()).ok()?;
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]).ok()?;
    }
    Some(hex::encode(hasher.finish().ok()?))
}

/// Facts fixed at start.
pub(super) struct Info {
    pub fips: bool,
    pub max_lease_seconds: u32,
    pub census_interval: u64,
    /// The audit checkpoint given with --audit-checkpoint verified at start.
    pub audit_checkpoint_verified: bool,
    /// When `Store::open` verified the audit chain and object state index.
    pub store_verified_at: SystemTime,
    /// The served database; `backup` records its last success next to it.
    pub database: std::path::PathBuf,
}

pub(super) struct Endpoint {
    info: Info,
    started: SystemTime,
    started_instant: Instant,
    /// SHA-256 of the running executable, computed in the background.
    binary_sha256: Arc<OnceLock<String>>,
    registry: Arc<Registry>,
    network: Arc<network::Metrics>,
    engine: Arc<Mutex<Engine>>,
}

impl Endpoint {
    pub(super) fn new(
        info: Info,
        registry: Arc<Registry>,
        network: Arc<network::Metrics>,
        engine: Arc<Mutex<Engine>>,
    ) -> Self {
        let binary_sha256 = Arc::new(OnceLock::new());
        let fill = binary_sha256.clone();
        tokio::task::spawn_blocking(move || {
            let digest = executable_sha256().unwrap_or_else(|| "unknown".into());
            let _ = fill.set(digest);
        });
        Self {
            info,
            started: SystemTime::now(),
            started_instant: Instant::now(),
            binary_sha256,
            registry,
            network,
            engine,
        }
    }

    /// The whole document. Store state is read under the engine lock on a
    /// blocking thread; everything else without it.
    pub(super) async fn render(&self) -> String {
        let engine = self.engine.clone();
        let store = tokio::task::spawn_blocking(move || {
            engine
                .lock()
                .ok()
                .map(|e| (e.store.healthy(), e.store.size().ok()))
        })
        .await
        .ok()
        .flatten();
        let mut out = Exposition::new();
        self.write_info(&mut out, store.as_ref().is_some_and(|(ok, _)| *ok));
        if let Some((_, Some(size))) = &store {
            out.family(
                "kmip_store_database_bytes",
                "Size of the SQLite main database file from its page count (the WAL is not included).",
                "gauge",
            );
            out.sample("kmip_store_database_bytes", &[], size.bytes as f64);
            out.family(
                "kmip_store_free_bytes",
                "Free pages inside the database file, in bytes.",
                "gauge",
            );
            out.sample("kmip_store_free_bytes", &[], size.free_bytes as f64);
        }
        self.registry.write(&mut out);
        self.network.write_prometheus(&mut out);
        out.finish()
    }

    fn write_info(&self, out: &mut Exposition, ready: bool) {
        let fips = if self.info.fips { "true" } else { "false" };
        let commit = option_env!("KEYTEND_KMIP_SERVER_COMMIT").unwrap_or("unknown");
        let binary = self
            .binary_sha256
            .get()
            .map(String::as_str)
            .unwrap_or("pending");
        out.family(
            "kmip_build_info",
            "Build of the running server (value 1). commit is set at build time by KEYTEND_KMIP_SERVER_COMMIT; binary_sha256 is the SHA-256 of the running executable.",
            "gauge",
        );
        out.sample(
            "kmip_build_info",
            &[
                ("version", env!("CARGO_PKG_VERSION")),
                ("commit", commit),
                ("binary_sha256", binary),
                ("openssl", openssl::version::version()),
                ("fips_mode", fips),
            ],
            1.0,
        );
        let gauge = |out: &mut Exposition, name: &str, help: &str, value: f64| {
            out.family(name, help, "gauge");
            out.sample(name, &[], value);
        };
        gauge(
            out,
            "kmip_fips_mode",
            "1 when the server runs in FIPS mode (docs/fips.md).",
            f64::from(u8::from(self.info.fips)),
        );
        let providers = keytend_kmip_server::fips::loaded_providers();
        if !providers.is_empty() {
            out.family(
                "kmip_fips_provider_info",
                "OpenSSL providers loaded in FIPS mode, as they report themselves (value 1).",
                "gauge",
            );
            let reported = |v: &Option<String>| v.clone().unwrap_or_else(|| "not reported".into());
            for p in &providers {
                let (name, version, build) = (
                    reported(&p.name),
                    reported(&p.version),
                    reported(&p.build_info),
                );
                out.sample(
                    "kmip_fips_provider_info",
                    &[
                        ("provider", p.id),
                        ("name", &name),
                        ("version", &version),
                        ("build_info", &build),
                    ],
                    1.0,
                );
            }
            out.family(
                "kmip_fips_provider_status",
                "Provider status read at scrape time: 1 running, 0 in its error state, -1 not reported.",
                "gauge",
            );
            for p in &providers {
                out.sample(
                    "kmip_fips_provider_status",
                    &[("provider", p.id)],
                    f64::from(p.status.unwrap_or(-1)),
                );
            }
        }
        gauge(
            out,
            "process_start_time_seconds",
            "Start time of the process since the Unix epoch, in seconds.",
            unix(self.started),
        );
        gauge(
            out,
            "kmip_uptime_seconds",
            "Seconds since the server started.",
            self.started_instant.elapsed().as_secs_f64(),
        );
        gauge(
            out,
            "kmip_ready",
            "1 when /readyz answers 200: the engine is available and the store's live-history check passes.",
            f64::from(u8::from(ready)),
        );
        gauge(
            out,
            "kmip_store_verified_timestamp_seconds",
            "When the audit chain and the object state index were last verified (at start; the server does not start when they fail).",
            unix(self.info.store_verified_at),
        );
        gauge(
            out,
            "kmip_store_audit_checkpoint_verified",
            "1 when an --audit-checkpoint was given and verified at start, 0 when none was given.",
            f64::from(u8::from(self.info.audit_checkpoint_verified)),
        );
        gauge(
            out,
            "kmip_last_backup_timestamp_seconds",
            "When the last successful backup of the database was taken, from <database>.last-backup, which backup writes when it can (0: none recorded).",
            keytend_kmip_server::maintenance::read_last_backup(&self.info.database).unwrap_or(0)
                as f64,
        );
        gauge(
            out,
            "kmip_lease_max_seconds",
            "--max-lease-seconds: the Lease Time stored on new objects (0: no lease limit).",
            f64::from(self.info.max_lease_seconds),
        );
        gauge(
            out,
            "kmip_object_census_interval_seconds",
            "--metrics-object-census-interval (0: no census).",
            self.info.census_interval as f64,
        );
    }
}

/// One census in pages of `CENSUS_PAGE` records; the engine lock is released
/// between pages. None when the engine or store failed.
async fn census(engine: &Arc<Mutex<Engine>>) -> Option<Census> {
    let started = Instant::now();
    let mut census = Census::default();
    let mut after: Option<String> = None;
    loop {
        let engine = engine.clone();
        let cursor = after.take();
        let page = tokio::task::spawn_blocking(move || {
            engine
                .lock()
                .ok()
                .and_then(|e| e.store.census_page(cursor.as_deref(), CENSUS_PAGE).ok())
        })
        .await
        .ok()
        .flatten()?;
        for (object_type, state) in page.objects {
            census.add(object_type, state);
        }
        census.unreadable += page.unreadable;
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    census.duration_seconds = started.elapsed().as_secs_f64();
    census.completed_at = unix(SystemTime::now());
    Some(census)
}

/// Run the object census now and then every `interval` seconds.
pub(super) async fn census_loop(
    engine: Arc<Mutex<Engine>>,
    registry: Arc<Registry>,
    interval: u64,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(interval));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match census(&engine).await {
            Some(census) => {
                if census.unreadable > 0 {
                    tracing::warn!(
                        unreadable = census.unreadable,
                        "object census found records that do not authenticate; run check-store"
                    );
                }
                registry.set_census(census);
            }
            None => tracing::warn!("object census failed; kmip_objects keeps the previous census"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn census_interval_is_zero_or_bounded() {
        assert_eq!(census_interval("0"), Ok(0));
        assert_eq!(census_interval("10"), Ok(10));
        assert_eq!(census_interval("86400"), Ok(86_400));
        assert!(census_interval("9").is_err());
        assert!(census_interval("86401").is_err());
        assert!(census_interval("-1").is_err());
        assert!(census_interval("x").is_err());
    }
}
