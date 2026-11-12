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

mod metrics_endpoint;
mod network;
mod server_http;
mod tls_profile;
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use keytend_kmip_server::{
    protocol::{
        Channel, DestroyedNameReuse, EcCurves, Engine, Failure, GetAttributesNone, LeaseStates,
        Lookup, Provisioning, TripleDesPolicy, Version, error_response, store_failure_response,
    },
    store::Store,
    ttlv,
};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslOptions, SslVerifyMode, SslVersion},
    x509::{store::X509Lookup, verify::X509VerifyFlags},
};
use serde::Deserialize;
use std::os::unix::fs::DirBuilderExt;
use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};
use tokio_openssl::SslStream;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Keytend KMIP lifecycle service (a partial KMIP implementation; read the README before deployment)."
)]
struct Args {
    /// FIPS mode (docs/fips.md): load OpenSSL's FIPS provider and refuse
    /// non-approved services. Also entered when the host kernel is in FIPS
    /// mode (/proc/sys/crypto/fips_enabled = 1).
    #[arg(long, global = true, env = "KMIP_FIPS", default_value_t = false)]
    fips: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(clap::Args)]
struct ServeOptions {
    /// Binary TTLV over TLS listener address.
    #[arg(long, env = "KMIP_LISTEN", default_value = "0.0.0.0:5696")]
    listen: SocketAddr,
    /// HTTPS listener address (TTLV, JSON or XML bodies); off unless set.
    #[arg(long, env = "KMIP_HTTPS_LISTEN")]
    https_listen: Option<SocketAddr>,
    /// HTTPS request path.
    #[arg(long, env = "KMIP_HTTPS_PATH", default_value = "/kmip")]
    https_path: String,
    /// Plain-HTTP health, readiness and metrics listener address.
    #[arg(long, env = "KMIP_HEALTH_LISTEN", default_value = "0.0.0.0:8080")]
    health_listen: SocketAddr,
    /// PEM server certificate chain.
    #[arg(long, env = "KMIP_CERT")]
    cert: PathBuf,
    /// PEM server private key.
    #[arg(long, env = "KMIP_KEY")]
    key: PathBuf,
    /// PEM CA bundle that client certificates must chain to.
    #[arg(long, env = "KMIP_CA")]
    ca: PathBuf,
    /// PEM CRL; when set, client chain revocation checks are required.
    #[arg(long, env = "KMIP_CRL")]
    crl: Option<PathBuf>,
    /// PEM trust anchors for KMIP Validate; independent of the mTLS CA.
    #[arg(long, env = "KMIP_VALIDATION_CA")]
    validation_ca: Option<PathBuf>,
    /// JSON policy mapping client certificate fingerprints to principals.
    #[arg(long, env = "KMIP_POLICY")]
    policy: PathBuf,
    /// Header-credential users and devices per certificate fingerprint, as
    /// salted password verifiers only (`keytend-kmip-server password-verifier`).
    /// Without it, every header credential fails.
    #[arg(long, env = "KMIP_USERS")]
    users: Option<PathBuf>,
    /// Accept users-file Hashed Password (S1) and One Time Password (TOTP
    /// seed) material. The server must be able to recompute both, so they
    /// are weaker than salted verifiers: S1 is a fast unsalted hash of the
    /// password, and the seed produces codes. Refused unless set.
    #[arg(
        long,
        env = "KMIP_ALLOW_STORED_CREDENTIAL_SECRETS",
        default_value_t = false
    )]
    allow_stored_credential_secrets: bool,
    /// SQLite store, created if missing.
    #[arg(long, env = "KMIP_DATABASE", default_value = "/data/kmip.sqlite")]
    database: PathBuf,
    /// 32-byte raw master key file from `generate-master-key`.
    #[arg(long, env = "KMIP_MASTER_KEY")]
    master_key: PathBuf,
    /// Independently retained audit checkpoint required before serving requests.
    #[arg(long, env = "KMIP_AUDIT_CHECKPOINT")]
    audit_checkpoint: Option<PathBuf>,
    /// Accept the KMIP 3.0 draft (CSD02).
    #[arg(long, env = "KMIP_EXPERIMENTAL_V3", default_value_t = false)]
    experimental_v3: bool,
    /// Legacy three-key 3DES: `disabled` (default), `legacy-decrypt` (Register,
    /// Import and Decrypt only) or `enabled` (also Create, Re-key and Encrypt,
    /// as the Symmetric Key Foundry profiles require). Single DES is never offered.
    #[arg(long, env = "KMIP_TRIPLE_DES", value_enum, default_value_t = TripleDesPolicy::Disabled)]
    triple_des: TripleDesPolicy,
    /// Offer the KMIP Interop operation (2.x/3.0) for interoperability test
    /// runs. The specification forbids it on a production server ("SHALL NOT
    /// be available in a production server"); off by default, logs a warning.
    #[arg(long, env = "KMIP_INTEROP_TEST_MODE", default_value_t = false)]
    interop_test_mode: bool,
    /// TLS policy of both listeners: `modern` (default, Mozilla intermediate
    /// TLS 1.2-1.3 restricted to FIPS-approved choices), `mozilla-intermediate`
    /// or a KMIP Profiles authentication-suite policy listed by
    /// `keytend-kmip-server tls-profiles`. The legacy policies log a warning.
    #[arg(long, env = "KMIP_TLS_PROFILE", value_enum, default_value_t = tls_profile::TlsProfile::Modern)]
    tls_profile: tls_profile::TlsProfile,
    /// Open connections allowed across both listeners (1-1024); further
    /// clients wait until one closes.
    #[arg(long, env = "KMIP_MAX_CONNECTIONS", default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..=1024))]
    max_connections: u32,
    /// Maximum Lease Time, in seconds, stored on new objects; 0 means no limit.
    #[arg(long, env = "KMIP_MAX_LEASE_SECONDS", default_value_t = keytend_kmip_server::protocol::DEFAULT_MAXIMUM_LEASE_SECONDS)]
    max_lease_seconds: u32,
    /// Close a binary or HTTPS connection that has waited this many seconds
    /// for its next request (default 300, at most one week); 0 never closes an
    /// idle connection. Each open connection holds one of --max-connections.
    /// Handshake, frame, header, body and write deadlines are unaffected.
    #[arg(long, env = "KMIP_IDLE_TIMEOUT", default_value_t = DEFAULT_IDLE_TIMEOUT, value_parser = clap::value_parser!(u64).range(0..=MAX_IDLE_TIMEOUT))]
    idle_timeout: u64,
    /// Names held only by Destroyed or Destroyed Compromised objects:
    /// `allow` (default) lets another object of the owner take them;
    /// `reserve` keeps them reserved (docs/interpretations.md).
    #[arg(long, env = "KMIP_DESTROYED_NAME_REUSE", value_enum, default_value_t = DestroyedNameReuse::Allow)]
    destroyed_name_reuse: DestroyedNameReuse,
    /// Lifecycle states Obtain Lease serves: `active-deactivated` (default)
    /// also leases Deactivated objects, which may still process protected
    /// data; `active` leases Active objects only (docs/lifecycle.md#leases).
    #[arg(long, env = "KMIP_LEASE_STATES", value_enum, default_value_t = LeaseStates::ActiveDeactivated)]
    lease_states: LeaseStates,
    /// 2.x/3.0 Get Attributes when none of the requested attributes exist:
    /// `empty-attributes` (default) returns the Unique Identifier and an empty
    /// Attributes structure (response table: Attributes REQUIRED);
    /// `identifier-only` returns the Unique Identifier alone (operation
    /// prose). See docs/interpretations.md.
    #[arg(long, env = "KMIP_GET_ATTRIBUTES_NONE", value_enum, default_value_t = GetAttributesNone::EmptyAttributes)]
    get_attributes_none: GetAttributesNone,
    /// Elliptic curves KMIP operations may use: `extended` (default) all 13
    /// implemented curves, P-224, P-256, P-384, P-521, secp256k1 and
    /// brainpoolP256/320/384/512 r1 and t1; `nist` the first four only. Keys
    /// stored on the other curves stay readable as stored under `nist` but
    /// cannot be used. TLS does not change; FIPS mode offers the NIST curves
    /// only (docs/interpretations.md).
    #[arg(long, env = "KMIP_EC_CURVES", value_enum, default_value_t = EcCurves::Extended)]
    ec_curves: EcCurves,
    #[command(flatten)]
    text_encoding: keytend_kmip_server::encoding::TextEncodingArgs,
    /// Serve Prometheus metrics at /metrics on the health listener: `on`
    /// (default) or `off`. Never on the KMIP listeners; the metrics carry no
    /// key material, identifiers, principals or attribute values
    /// (docs/metrics.md).
    #[arg(long, env = "KMIP_METRICS", value_enum, default_value_t = metrics_endpoint::MetricsSetting::On)]
    metrics: metrics_endpoint::MetricsSetting,
    /// Seconds between object censuses (kmip_objects by Object Type and
    /// State): 0 runs none, otherwise 10-86400 (default 300). A census reads
    /// every object record, 256 per engine lock.
    #[arg(long, env = "KMIP_METRICS_OBJECT_CENSUS_INTERVAL", default_value_t = metrics_endpoint::DEFAULT_CENSUS_INTERVAL, value_parser = metrics_endpoint::census_interval)]
    metrics_object_census_interval: u64,
    /// Size of the decrypted-object cache in MiB: 0 turns it off, otherwise
    /// 1-65536 (default 64). Cached objects include their key material
    /// (docs/configuration.md#object-cache).
    #[arg(long, env = "KMIP_OBJECT_CACHE_MIB", default_value_t = 64, value_parser = clap::value_parser!(u64).range(0..=65536))]
    object_cache_mib: u64,
    /// Seconds a cached object may go unused before it is dropped: 1-86400
    /// (default 600).
    #[arg(long, env = "KMIP_OBJECT_CACHE_TTL", default_value_t = 600, value_parser = clap::value_parser!(u64).range(1..=86400))]
    object_cache_ttl: u64,
    /// PEM CA certificate that issues Re-Provision client certificates; with
    /// --provisioning-ca-key it offers Re-Provision (2.0 and later). Use a
    /// dedicated sub-CA that is also in the --ca bundle
    /// (docs/re-provision.md).
    #[arg(long, env = "KMIP_PROVISIONING_CA", requires = "provisioning_ca_key")]
    provisioning_ca: Option<PathBuf>,
    /// PEM private key of --provisioning-ca; the file must not be
    /// accessible to other users.
    #[arg(long, env = "KMIP_PROVISIONING_CA_KEY", requires = "provisioning_ca")]
    provisioning_ca_key: Option<PathBuf>,
}
/// Idle connection close, in seconds (`--idle-timeout`).
const DEFAULT_IDLE_TIMEOUT: u64 = 300;
const MAX_IDLE_TIMEOUT: u64 = 7 * 24 * 3600;
/// A setting's command-line spelling (`active-deactivated`), for the log.
fn cli_name<T: clap::ValueEnum>(value: &T) -> String {
    value
        .to_possible_value()
        .map_or_else(String::new, |v| v.get_name().to_owned())
}
/// The effective text encoding for the log: the preset's name when no element
/// option changes it, otherwise every element form as `option=value`.
fn text_encoding_label(effective: &keytend_kmip_server::encoding::TextEncoding) -> String {
    use keytend_kmip_server::encoding::{Preset, TextEncoding};
    if let Some(preset) = <Preset as clap::ValueEnum>::value_variants()
        .iter()
        .find(|p| TextEncoding::preset(**p) == *effective)
    {
        return cli_name(preset);
    }
    let e = effective;
    [
        ("json-tags", cli_name(&e.json_tags)),
        ("json-enumerations", cli_name(&e.json_enumerations)),
        ("json-masks", cli_name(&e.json_masks)),
        ("json-integers", cli_name(&e.json_integers)),
        ("json-long-integers", cli_name(&e.json_long_integers)),
        ("json-big-integers", cli_name(&e.json_big_integers)),
        ("json-intervals", cli_name(&e.json_intervals)),
        (
            "json-date-time-extended",
            cli_name(&e.json_date_time_extended),
        ),
        ("json-booleans", cli_name(&e.json_booleans)),
        ("json-date-times", cli_name(&e.json_date_times)),
        ("xml-tags", cli_name(&e.xml_tags)),
        ("xml-enumerations", cli_name(&e.xml_enumerations)),
        ("xml-masks", cli_name(&e.xml_masks)),
    ]
    .iter()
    .map(|(option, value)| format!("{option}={value}"))
    .collect::<Vec<_>>()
    .join(",")
}
/// Flag combinations clap's declarative rules cannot express (they ignore a
/// requirement on an argument that conflicts with one given). An invalid
/// invocation exits 2, like any other usage error.
fn check_combinations(command: &Command) -> Result<(), &'static str> {
    match command {
        Command::Backup {
            output_dir: None,
            retain: Some(_),
            ..
        } => Err("--retain needs --output-dir"),
        Command::RotateMasterKey {
            new_master_key,
            output,
            create_directory,
            in_place: true,
            previous_master_key,
            ..
        } => {
            if new_master_key.is_some() || output.is_some() || *create_directory {
                Err(
                    "--in-place rotates the database itself: leave out --new-master-key, --output and --create-directory (--master-key is the new key)",
                )
            } else if previous_master_key.is_none() {
                Err("--in-place needs --previous-master-key")
            } else {
                Ok(())
            }
        }
        Command::RotateMasterKey {
            new_master_key,
            output,
            in_place: false,
            previous_master_key,
            checkpoint_output,
            revert,
            ..
        } => {
            if previous_master_key.is_some() || checkpoint_output.is_some() || *revert {
                Err("--previous-master-key, --checkpoint-output and --revert need --in-place")
            } else if new_master_key.is_none() || output.is_none() {
                Err("rotate-master-key needs --new-master-key and --output (or --in-place)")
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}
/// For `backup --if-exists`: true only when the database (or its directory)
/// has really not been created. Errors other than "not found" are errors,
/// and a missing main file during an unfinished restore or rotation (whose
/// record is next to it) is refused, not taken for absence.
fn database_absent(database: &Path) -> Result<bool> {
    let missing = |path: &Path| -> Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(anyhow::Error::new(e).context(format!("inspect {}", path.display()))),
        }
    };
    if !missing(database)? {
        return Ok(false);
    }
    let dir = database
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if missing(dir)? {
        return Ok(true);
    }
    // Under the read guard, which refuses an unfinished cutover.
    let _read = keytend_kmip_server::maintenance::read_guard(database)?;
    missing(database)
}
/// The `--master-key` to use: the only one given, or the first of several
/// that opens the store (named on standard output). Call it under the read
/// guard.
fn choose_master_key(database: &Path, keys: &[PathBuf]) -> Result<PathBuf> {
    if let [only] = keys {
        return Ok(only.clone());
    }
    for key in keys {
        // A candidate that is not a usable key file (missing, unreadable,
        // malformed) is skipped with a note; the store itself must be
        // readable.
        match Store::master_key_opens(database, key) {
            Ok(true) => {
                println!("Master key {} opens {}", key.display(), database.display());
                return Ok(key.clone());
            }
            Ok(false) => {}
            Err(error) if Store::open_read_only_check_key_file(key).is_err() => {
                eprintln!("note: skipped --master-key {}: {error:#}", key.display());
            }
            Err(error) => return Err(error),
        }
    }
    bail!(
        "none of the {} --master-key files opens {}",
        keys.len(),
        database.display()
    )
}
/// What `check-store` and `backup` verified of a store older than this binary.
fn older_schema_note(verification: &keytend_kmip_server::store::Verification) -> String {
    format!(
        "Storage schema {} is older than this release's {}: verified read-only without upgrading it; the server builds and authenticates its object index when it first opens the store",
        verification.storage_schema,
        keytend_kmip_server::store::STORAGE_SCHEMA
    )
}
/// Whether `serve` got `--ec-curves` or `KMIP_EC_CURVES` rather than the
/// default. FIPS mode notes an explicit `extended` only, so the default does
/// not log on every FIPS start.
fn ec_curves_chosen(matches: &clap::ArgMatches) -> bool {
    use clap::parser::ValueSource;
    matches.subcommand_matches("serve").is_some_and(|m| {
        matches!(
            m.value_source("ec_curves"),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        )
    })
}
/// The idle limit, or `None` when idle connections stay open.
fn idle_limit(seconds: u64) -> Option<Duration> {
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

#[derive(Subcommand)]
enum Command {
    /// Serve binary TTLV over mutually authenticated TLS. No plaintext mode.
    Serve(Box<ServeOptions>),
    /// Print the TLS profile policies (versions, suites, groups) as JSON.
    TlsProfiles,
    /// Generate a 256-bit raw master key; refuses to overwrite a file.
    GenerateMasterKey {
        /// Key file to create (mode 0600); must not exist.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a store or backup read-only: master key, SQLite integrity, every
    /// object record and the audit chain. Never writes to or upgrades the
    /// database (SQLite may create empty -wal and -shm files next to a stopped one).
    CheckStore {
        /// SQLite store or backup to verify; may be in use by a running server.
        #[arg(long)]
        database: PathBuf,
        /// Master key the store is encrypted under. Give it more than once to
        /// try several keys (for example the current and the next master key
        /// around a rotation): the first that opens the store is used and named
        /// in the output.
        #[arg(long, required = true)]
        master_key: Vec<PathBuf>,
        /// Fail if the store is older than, or diverges from, this audit checkpoint.
        #[arg(long)]
        audit_checkpoint: Option<PathBuf>,
    },
    /// Export an authenticated audit floor to independently protected storage. Refuses overwrite.
    AuditCheckpoint {
        /// SQLite store to checkpoint; may be in use by a running server. It is only read.
        #[arg(long)]
        database: PathBuf,
        /// Master key the store is encrypted under.
        #[arg(long)]
        master_key: PathBuf,
        /// Checkpoint file to create; must not exist.
        #[arg(long)]
        output: PathBuf,
        /// Require this trusted floor before exporting another checkpoint.
        #[arg(long)]
        previous: Option<PathBuf>,
    },
    /// Create a consistent, verified encrypted database backup. Refuses overwrite.
    ///
    /// The store is only read, and may be in use by a running server; an
    /// older store is copied as it is, without an upgrade. On success the
    /// time is recorded in <database>.last-backup when that directory is
    /// writable (the server reports it as kmip_last_backup_timestamp_seconds).
    Backup {
        /// SQLite store to copy; may be in use by a running server.
        #[arg(long)]
        database: PathBuf,
        /// Master key the store is encrypted under; the backup keeps it. Give it more than once to
        /// try several keys (for example the current and the next master key
        /// around a rotation): the first that opens the store is used and named
        /// in the output.
        #[arg(long, required = true)]
        master_key: Vec<PathBuf>,
        /// If the database does not exist yet (a server that has never
        /// started), say so and exit 0 instead of failing.
        #[arg(long)]
        if_exists: bool,
        /// Backup file to create in an existing directory; must not exist.
        #[arg(
            long,
            required_unless_present = "output_dir",
            conflicts_with = "output_dir"
        )]
        output: Option<PathBuf>,
        /// Existing directory to write backup-<UTC time>.sqlite into (mode
        /// 0600). The copy is verified, then latest.json in the directory is
        /// replaced with its name, size, time and verification result.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        /// With --output-dir: afterwards keep only the newest N
        /// backup-<UTC time>.sqlite files in the directory (N at least 1).
        /// No other file is removed.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
        retain: Option<u32>,
    },
    /// Re-encrypt the store under a new master key.
    ///
    /// Without --in-place: write a verified snapshot encrypted with
    /// --new-master-key to --output; stop serving before the cutover.
    ///
    /// With --in-place: rotate the database itself from
    /// --previous-master-key to --master-key, under the store lock (the
    /// server must be stopped). The database from before is kept in
    /// pre-rotation-<UTC time>/ next to it. Running it again does nothing
    /// once the store opens with --master-key, and finishes a run that was
    /// interrupted.
    RotateMasterKey {
        /// SQLite store to re-encrypt; stop the server first.
        #[arg(long)]
        database: PathBuf,
        /// Current master key. With --in-place: the new key, which the server
        /// uses after the rotation.
        #[arg(long)]
        master_key: PathBuf,
        /// New master key (from generate-master-key); must differ from the current one.
        /// Not with --in-place.
        #[arg(long)]
        new_master_key: Option<PathBuf>,
        /// Fail if the store is older than, or diverges from, this audit
        /// checkpoint. With --in-place, a checkpoint of the key before the
        /// rotation is accepted while the pre-rotation copy it verifies is kept.
        #[arg(long)]
        audit_checkpoint: Option<PathBuf>,
        /// Re-encrypted snapshot to create; must not exist. Not with --in-place.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Create the output's parent directory with mode 0700 first; it must not exist.
        /// Lets a Kubernetes Job rotate without a shell in the image.
        #[arg(long)]
        create_directory: bool,
        /// Rotate the database in place (see above).
        #[arg(long)]
        in_place: bool,
        /// With --in-place: the master key the store is encrypted under
        /// before the rotation.
        #[arg(long)]
        previous_master_key: Option<PathBuf>,
        /// With --in-place: write an audit checkpoint of the store, under the
        /// key it is left with, to this file (or require that the existing
        /// file verifies). Start the server with it and keep a copy in the
        /// checkpoint store.
        #[arg(long)]
        checkpoint_output: Option<PathBuf>,
        /// With --in-place: put back the database from the newest
        /// pre-rotation-<UTC time>/ (it must open with --previous-master-key)
        /// and move the rotated one to post-rotation-<UTC time>/. Writes
        /// since the rotation are not carried back. Does nothing if the store
        /// already opens with --previous-master-key.
        #[arg(long)]
        revert: bool,
    },
    /// Verify a backup and install it as the database, keeping the previous one.
    ///
    /// Stop the server first (the command takes the store lock). The backup
    /// is verified read-only first; if that fails nothing changes. Then the
    /// current database files move to pre-restore-<id>/ next to the database,
    /// and a verified copy of the backup takes their place. The database need
    /// not exist (recovery onto a new volume). Running it again with the same
    /// --id does nothing.
    Restore {
        /// Backup to restore (written by `backup`); it is only read.
        #[arg(long)]
        from: PathBuf,
        /// Name of this restore: 1-64 letters, digits, '.', '_' or '-'.
        #[arg(long)]
        id: String,
        /// Database to replace (for example /data/kmip.sqlite).
        #[arg(long)]
        database: PathBuf,
        /// Master key that opens the backup; start the server with this key.
        #[arg(long)]
        master_key: PathBuf,
        /// Refuse a backup older than, or diverging from, this audit checkpoint.
        #[arg(long)]
        audit_checkpoint: Option<PathBuf>,
    },
    /// Read a password from standard input (one line) and print the users-file
    /// `password_verifier` value: PBKDF2-HMAC-SHA-256, 600 000 iterations.
    PasswordVerifier,
    /// Load the OpenSSL FIPS provider as `serve --fips` does and print what
    /// was found; fails if it cannot be loaded or another provider leaks in.
    FipsCheck,
    /// Container readiness probe: exit 0 when GET /readyz answers 200.
    Healthcheck {
        /// Health listener to probe (numeric IP:port). KMIP_HEALTH_LISTEN is
        /// not read; pass this when the listener moves.
        #[arg(long, default_value = "127.0.0.1:8080")]
        address: SocketAddr,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    principals: HashMap<String, Principal>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Principal {
    name: String,
    operations: Vec<u32>,
    #[serde(default)]
    object_grants: Vec<keytend_kmip_server::authorization::ObjectGrant>,
    /// Opt-in server-to-client Notify (27) and Put (28) delivery for objects
    /// this principal owns. Absent: the server never initiates messages.
    #[serde(default)]
    client_endpoint: Option<ClientEndpoint>,
    /// "certificate" (default): the certificate principal is the client
    /// identity and owns every object, whatever header credentials verify.
    /// "credential": a request whose header credentials verify acts as that
    /// user or device of the principal (Profiles 2.0/2.1 section 3.1.3).
    #[serde(default)]
    client_identity: ClientIdentity,
}
#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ClientIdentity {
    #[default]
    Certificate,
    Credential,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientEndpoint {
    /// Dial-out transport. All five fields, or none: without them messages
    /// travel only over a channel the principal reversed with Set Endpoint
    /// Role (50), which the principal must then be allowed.
    /// host:port of the principal's KMIP client listener.
    #[serde(default)]
    address: Option<String>,
    /// Name or IP address that the endpoint certificate must match.
    #[serde(default)]
    server_name: Option<String>,
    /// PEM trust anchors for the endpoint certificate (nothing else is trusted).
    #[serde(default)]
    ca: Option<PathBuf>,
    /// PEM certificate chain and key this server presents to the endpoint.
    #[serde(default)]
    certificate: Option<PathBuf>,
    #[serde(default)]
    key: Option<PathBuf>,
    /// Protocol version of the messages, "1.0" through "2.1".
    protocol_version: String,
    /// 27 (Notify) and/or 28 (Put).
    operations: Vec<u32>,
    /// Dial-out framing: "ttlv" (default) or "https" (HTTP/1.1 POST, Profiles
    /// 1.3-2.1 section 5.3.2: an HTTPS server behaves as an HTTPS client).
    #[serde(default)]
    transport: EndpointTransport,
    /// HTTPS request target (default "/kmip"); only with "https".
    #[serde(default)]
    target: Option<String>,
}
#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum EndpointTransport {
    #[default]
    Ttlv,
    Https,
}
/// address, server_name, ca, certificate, key.
type DialFields<'a> = (&'a str, &'a str, &'a Path, &'a Path, &'a Path);
impl ClientEndpoint {
    fn version(&self) -> Result<Version> {
        let (major, minor) = self
            .protocol_version
            .split_once('.')
            .context("client endpoint protocol_version must be MAJOR.MINOR")?;
        let version = Version(major.parse()?, minor.parse()?);
        anyhow::ensure!(
            Version::supported(false).contains(&version),
            "client endpoint protocol_version must be 1.0 through 2.1"
        );
        Ok(version)
    }
    /// The dial-out fields, if configured.
    fn dial(&self) -> Result<Option<DialFields<'_>>> {
        match (
            &self.address,
            &self.server_name,
            &self.ca,
            &self.certificate,
            &self.key,
        ) {
            (Some(a), Some(n), Some(ca), Some(c), Some(k)) => Ok(Some((a, n, ca, c, k))),
            (None, None, None, None, None) => Ok(None),
            _ => bail!("client endpoint address, server_name, ca, certificate and key go together"),
        }
    }
    fn transport(&self) -> keytend_kmip_server::delivery::Transport {
        match self.transport {
            EndpointTransport::Ttlv => keytend_kmip_server::delivery::Transport::Ttlv,
            EndpointTransport::Https => keytend_kmip_server::delivery::Transport::Https {
                target: self
                    .target
                    .clone()
                    .unwrap_or_else(|| keytend_kmip_server::delivery::HTTPS_TARGET.to_owned()),
            },
        }
    }
    fn validate(&self, principal: &Principal) -> Result<()> {
        let version = self.version()?;
        match self.transport {
            EndpointTransport::Ttlv => anyhow::ensure!(
                self.target.is_none(),
                "client endpoint target applies only to the https transport"
            ),
            // A reversed channel is a TTLV connection; HTTPS needs dial-out.
            EndpointTransport::Https => anyhow::ensure!(
                self.address.is_some()
                    && self
                        .target
                        .as_deref()
                        .is_none_or(keytend_kmip_server::delivery::valid_target),
                "the https client endpoint transport needs an address and an origin-form target"
            ),
        }
        match self.dial()? {
            Some((address, server_name, ..)) => {
                let (host, port) = address
                    .rsplit_once(':')
                    .context("client endpoint address must be host:port")?;
                anyhow::ensure!(
                    !host.is_empty()
                        && host.len() <= 253
                        && port.parse::<u16>().is_ok_and(|p| p != 0)
                        && !server_name.is_empty()
                        && server_name.len() <= 253
                        && !address
                            .chars()
                            .chain(server_name.chars())
                            .any(|c| c.is_control() || c.is_whitespace()),
                    "invalid client endpoint address or server name"
                );
            }
            // Only a reversed channel can carry the messages: Set Endpoint
            // Role is defined from 2.0 (2.0 section 6.1.48).
            None => anyhow::ensure!(
                version >= Version(2, 0) && principal.operations.contains(&50),
                "a client endpoint without an address needs protocol 2.0 or 2.1 and Set Endpoint Role (50)"
            ),
        }
        let mut operations = self.operations.clone();
        operations.sort();
        operations.dedup();
        anyhow::ensure!(
            !operations.is_empty()
                && operations.len() == self.operations.len()
                && operations.iter().all(|op| matches!(op, 27 | 28)),
            "client endpoint operations must be distinct Notify (27) or Put (28)"
        );
        // Delivery reveals no more than the principal may read itself:
        // Notify sends attribute values, Put sends what Get returns.
        anyhow::ensure!(
            !operations.contains(&27) || principal.operations.contains(&11),
            "Notify delivery requires the principal to be allowed Get Attributes (11)"
        );
        anyhow::ensure!(
            !operations.contains(&28) || principal.operations.contains(&10),
            "Put delivery requires the principal to be allowed Get (10)"
        );
        Ok(())
    }
}
/// Users and devices that request-header credentials (every protocol version)
/// can name, keyed by the certificate fingerprint of the principal they belong
/// to. Kept apart from the policy so releases that reject unknown policy
/// fields still accept the same policy file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Users {
    users: HashMap<String, Vec<keytend_kmip_server::credentials::PolicyUser>>,
    #[serde(default)]
    devices: HashMap<String, Vec<keytend_kmip_server::credentials::PolicyDevice>>,
}
#[derive(Default)]
struct Credentials {
    users: HashMap<String, Vec<keytend_kmip_server::credentials::PolicyUser>>,
    devices: HashMap<String, Vec<keytend_kmip_server::credentials::PolicyDevice>>,
}
impl Credentials {
    /// Users-file verifiers in the pre-PBKDF2 scrypt form.
    fn legacy_verifiers(&self) -> usize {
        let users = self.users.values().flatten().flat_map(|u| {
            [
                Some(&u.password_scrypt),
                u.hashed_password.as_ref().map(|h| &h.s2_scrypt),
            ]
        });
        let devices = self
            .devices
            .values()
            .flatten()
            .map(|d| Some(&d.password_scrypt));
        users
            .chain(devices)
            .flatten()
            .filter(|v| v.is_legacy())
            .count()
    }
}
/// Settings FIPS mode cannot run with; refused before anything starts.
fn fips_settings(options: &ServeOptions) -> Result<()> {
    if options.triple_des != TripleDesPolicy::Disabled {
        bail!(
            "FIPS mode needs KMIP_TRIPLE_DES=disabled: SP 800-131A Rev. 2 disallows TDEA encryption and the RHEL 9 FIPS provider offers no TDEA, so legacy-decrypt is refused as well"
        );
    }
    if !options.tls_profile.fips_approved() {
        bail!(
            "FIPS mode needs an approved TLS profile (modern, kmip-1-suite-b-128 or kmip-1-suite-b-192); {:?} uses ChaCha20-Poly1305, X25519, static-RSA key transport or TLS 1.0/1.1",
            options.tls_profile
        );
    }
    Ok(())
}
/// Certificates of one principal (e.g. during rotation) must agree on its entries.
fn by_principal<T: PartialEq>(
    entries: HashMap<String, Vec<T>>,
    policy: &Policy,
    validate: fn(&[T]) -> Result<()>,
) -> Result<HashMap<String, Vec<T>>> {
    let mut by_principal: HashMap<String, Vec<T>> = HashMap::new();
    for (fingerprint, entries) in entries {
        let principal = policy
            .principals
            .get(&fingerprint)
            .context("users file names a certificate fingerprint absent from the policy")?;
        validate(&entries)?;
        if let Some(existing) = by_principal.get(&principal.name)
            && *existing != entries
        {
            bail!("certificates of one principal disagree on its users or devices");
        }
        by_principal.insert(principal.name.clone(), entries);
    }
    Ok(by_principal)
}
fn read_users(path: &Path, policy: &Policy, allow_secrets: bool) -> Result<Credentials> {
    let file: Users = serde_json::from_slice(&fs::read(path)?)?;
    if !allow_secrets && file.users.values().flatten().any(|u| u.stores_secrets()) {
        bail!(
            "users file holds hashed_password or one_time_password material; \
             set --allow-stored-credential-secrets to accept it"
        );
    }
    Ok(Credentials {
        users: by_principal(
            file.users,
            policy,
            keytend_kmip_server::credentials::validate_users,
        )?,
        devices: by_principal(
            file.devices,
            policy,
            keytend_kmip_server::credentials::validate_devices,
        )?,
    })
}
/// The policy entry for a new connection's certificate, and the policy
/// fingerprint that names it. The store decides first (docs/re-provision.md):
/// a fingerprint a Re-Provision retired is refused even if the policy lists
/// it; a replacement fingerprint uses the entry of the certificate it
/// replaced, or its own entry once the operator has added it under the same
/// principal name, and never an entry of another principal. Otherwise the
/// policy alone decides. None: treat the certificate as unlisted.
fn resolve_principal(
    policy: &Policy,
    lookup: &Lookup,
    fingerprint: &str,
) -> Option<(Principal, String)> {
    match lookup {
        Lookup::Retired => None,
        Lookup::Unknown => policy
            .principals
            .get(fingerprint)
            .map(|entry| (entry.clone(), fingerprint.to_owned())),
        Lookup::Replacement {
            policy_fingerprint,
            principal,
        } => {
            if policy
                .principals
                .get(fingerprint)
                .is_some_and(|direct| direct.name != *principal)
            {
                return None;
            }
            let (entry, key) = match policy.principals.get(policy_fingerprint) {
                Some(entry) => (entry, policy_fingerprint.as_str()),
                None => (policy.principals.get(fingerprint)?, fingerprint),
            };
            (entry.name == *principal).then(|| (entry.clone(), key.to_owned()))
        }
    }
}
fn read_policy(path: &Path) -> Result<Policy> {
    let p: Policy = serde_json::from_slice(&fs::read(path)?)?;
    if p.principals.is_empty() {
        bail!("policy must authorize at least one certificate fingerprint");
    }
    for (fingerprint, principal) in &p.principals {
        keytend_kmip_server::authorization::validate(&principal.object_grants)?;
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || principal.name.is_empty()
            || principal.name.len() > 128
            || principal.name.contains('\0')
            || principal.operations.iter().any(|op| !(1..=66).contains(op))
        {
            bail!("invalid fingerprint or principal in policy");
        }
        if p.principals.values().any(|other| {
            other.name == principal.name && other.client_identity != principal.client_identity
        }) {
            bail!("certificates of one principal disagree on its client_identity");
        }
        if let Some(endpoint) = &principal.client_endpoint {
            endpoint.validate(principal)?;
            if p.principals.values().any(|other| {
                other.name == principal.name
                    && other.client_endpoint.is_some()
                    && !std::ptr::eq(other, principal)
            }) {
                bail!("a principal name may configure only one client endpoint");
            }
        }
    }
    Ok(p)
}
/// Subscriptions and TLS endpoints for principals with a client endpoint.
fn server_to_client(
    policy: &Policy,
) -> Result<(
    HashMap<String, keytend_kmip_server::protocol::Subscription>,
    HashMap<String, keytend_kmip_server::delivery::Endpoint>,
)> {
    let mut subscriptions = HashMap::new();
    let mut endpoints = HashMap::new();
    for principal in policy.principals.values() {
        let Some(e) = &principal.client_endpoint else {
            continue;
        };
        let version = e.version()?;
        subscriptions.insert(
            principal.name.clone(),
            keytend_kmip_server::protocol::Subscription {
                version,
                notify: e.operations.contains(&27),
                put: e.operations.contains(&28),
            },
        );
        let dial = match e.dial()? {
            Some((address, server_name, ca, certificate, key)) => {
                Some(keytend_kmip_server::delivery::Dial {
                    address: address.to_owned(),
                    server_name: server_name.to_owned(),
                    connector: keytend_kmip_server::delivery::connector(ca, certificate, key)
                        .with_context(|| {
                            format!("client endpoint TLS for principal {}", principal.name)
                        })?,
                    transport: e.transport(),
                })
            }
            None => None,
        };
        endpoints.insert(
            principal.name.clone(),
            keytend_kmip_server::delivery::Endpoint { dial, version },
        );
    }
    Ok((subscriptions, endpoints))
}
/// Audit each delivery outcome. Runs off the request path; the engine is
/// locked only briefly in a blocking task.
fn delivery_report(
    engine: std::sync::Weak<Mutex<Engine>>,
) -> keytend_kmip_server::delivery::Report {
    Arc::new(move |d: keytend_kmip_server::delivery::Delivered| {
        match &d.outcome {
            Ok(()) => {
                tracing::info!(owner=%d.owner, operation=d.operation, object=?d.object, "server-to-client message delivered")
            }
            Err(error) => {
                tracing::warn!(owner=%d.owner, operation=d.operation, object=?d.object, %error, "server-to-client delivery failed")
            }
        }
        let Some(engine) = engine.upgrade() else {
            return;
        };
        tokio::task::spawn_blocking(move || {
            let status = if d.outcome.is_ok() { 0 } else { 1 };
            match engine.lock() {
                Ok(engine) => {
                    if let Err(error) =
                        engine
                            .store
                            .audit(&d.owner, d.operation, d.object.as_deref(), status)
                    {
                        tracing::error!(%error, "server-to-client audit failed");
                    }
                }
                Err(_) => tracing::error!("storage mutex poisoned; delivery outcome not audited"),
            }
        });
    })
}
fn tls(
    cert: &Path,
    key: &Path,
    ca: &Path,
    crl: Option<&Path>,
    profile: tls_profile::TlsProfile,
) -> Result<SslAcceptor> {
    // Before OpenSSL loads the key, so every build refuses an unsupported curve alike.
    let leaf = openssl::x509::X509::stack_from_pem(&fs::read(cert)?)?
        .into_iter()
        .next()
        .context("server certificate file has no certificate")?;
    if !tls_profile::supported_curve(&leaf) {
        bail!(
            "the server certificate's EC key is on an unsupported curve (docs/interpretations.md)"
        );
    }
    // NIST SP 800-131A for every policy: no SHA-1 (or weaker) certificate
    // signatures and keys of at least 112-bit strength, on both sides.
    tls_profile::certificate_strength(&leaf)
        .map_err(|e| anyhow::anyhow!("the server certificate {e}"))?;
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_certificate_chain_file(cert)?;
    builder.set_private_key_file(key, SslFiletype::PEM)?;
    builder.check_private_key()?;
    builder.set_ca_file(ca)?;
    builder.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        |ok, ctx| {
            tls_profile::supported_curve_chain(ok, ctx) && tls_profile::strong_chain(true, ctx)
        },
    );
    if let Some(policy) = profile.policy() {
        tls_profile::apply(&mut builder, policy, &leaf)?;
    } else if profile == tls_profile::TlsProfile::Modern {
        keytend_kmip_server::fips::tls::restrict(&mut builder).context(
            "the linked OpenSSL lacks a suite, group or signature algorithm of the modern policy",
        )?;
    }
    builder.set_verify_depth(4);
    builder.set_options(SslOptions::NO_COMPRESSION | SslOptions::NO_TICKET);
    if let Some(crl) = crl {
        let lookup = builder.cert_store_mut().add_lookup(X509Lookup::file())?;
        lookup.load_crl_file(crl, SslFiletype::PEM)?;
        builder
            .cert_store_mut()
            .set_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL)?;
    }
    Ok(builder.build())
}
/// Verifies a client certificate as the listener does.
type ClientVerifier =
    Box<dyn Fn(&openssl::x509::X509, &[openssl::x509::X509]) -> Result<(), String> + Send + Sync>;
/// The listener's client-certificate verification outside a handshake, from
/// the same inputs as `tls()`: the `--ca` trust anchors, `--crl` with
/// CRL_CHECK and CRL_CHECK_ALL, depth 4, purpose sslclient, the curve and
/// strength checks of every chain certificate, and the Suite B rules of the
/// profile. `chain` holds untrusted intermediates (the ones a client sent).
/// Re-Provision checks every new certificate with it before it is recorded
/// (docs/re-provision.md).
fn listener_verifier(
    ca: &Path,
    crl: Option<&Path>,
    profile: tls_profile::TlsProfile,
) -> Result<ClientVerifier> {
    use openssl::x509::{
        X509PurposeId, X509StoreContext,
        store::X509StoreBuilder,
        verify::{X509VerifyFlags, X509VerifyParam},
    };
    let mut builder = X509StoreBuilder::new()?;
    {
        let lookup = builder.add_lookup(X509Lookup::file())?;
        lookup.load_cert_file(ca, SslFiletype::PEM)?;
        if let Some(crl) = crl {
            lookup.load_crl_file(crl, SslFiletype::PEM)?;
        }
    }
    let suite_b = profile.policy().and_then(|p| p.suite_b);
    let mut flags = X509VerifyFlags::empty();
    if crl.is_some() {
        flags |= X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL;
    }
    if let Some(level) = suite_b {
        flags |= level.verify_flags();
    }
    let mut param = X509VerifyParam::new()?;
    param.set_flags(flags)?;
    param.set_depth(4);
    param.set_purpose(X509PurposeId::SSL_CLIENT)?;
    builder.set_param(&param)?;
    let store = builder.build();
    Ok(Box::new(move |leaf, chain| {
        let mut untrusted = openssl::stack::Stack::new().map_err(|e| e.to_string())?;
        for certificate in chain {
            untrusted
                .push(certificate.clone())
                .map_err(|e| e.to_string())?;
        }
        let mut context = X509StoreContext::new().map_err(|e| e.to_string())?;
        context
            .init(&store, leaf, &untrusted, |ctx| {
                if !ctx.verify_cert()? {
                    return Ok(Err(format!(
                        "{} (depth {})",
                        ctx.error().error_string(),
                        ctx.error_depth()
                    )));
                }
                for (depth, certificate) in ctx.chain().into_iter().flatten().enumerate() {
                    if !tls_profile::supported_curve(certificate) {
                        return Ok(Err(format!("depth {depth}: unsupported EC curve")));
                    }
                    if let Err(reason) = tls_profile::certificate_strength(certificate) {
                        return Ok(Err(format!("depth {depth}: {reason}")));
                    }
                }
                if suite_b.is_some()
                    && let Err(reason) = tls_profile::suite_b_end_entity(leaf)
                {
                    return Ok(Err(format!("Suite B: {reason}")));
                }
                Ok(Ok(()))
            })
            .map_err(|e| e.to_string())?
    }))
}
/// `--provisioning-ca` and `--provisioning-ca-key` (docs/re-provision.md):
/// the CA and key checks of `Provisioning::load`, the CA's strength, its
/// presence in the `--ca` bundle, and a self-test that issues a client
/// certificate (P-384 under Suite B 192, P-256 under Suite B 128, otherwise
/// RSA-2048) and runs it through the listener verifier.
#[allow(clippy::too_many_arguments)]
fn provisioning(
    ca_file: &Path,
    key_file: &Path,
    server_certificate: &Path,
    trust: &Path,
    crl: Option<&Path>,
    profile: tls_profile::TlsProfile,
    fips: bool,
    policy: &Policy,
) -> Result<Provisioning> {
    let _fips = keytend_kmip_server::fips::enter(fips);
    // Certificates that are credentials already: an adopted one is none of
    // them.
    let mut fingerprints: std::collections::HashSet<String> =
        policy.principals.keys().cloned().collect();
    let server = openssl::x509::X509::stack_from_pem(&fs::read(server_certificate)?)?
        .into_iter()
        .next()
        .context("server certificate file has no certificate")?;
    fingerprints.insert(hex::encode(server.digest(MessageDigest::sha256())?));
    let provisioning = Provisioning::load(
        ca_file,
        key_file,
        listener_verifier(trust, crl, profile)?,
        fingerprints,
    )?;
    let ca = provisioning.certificate();
    tls_profile::certificate_strength(ca)
        .map_err(|e| anyhow::anyhow!("the provisioning CA certificate {e}"))?;
    let der = ca.to_der()?;
    anyhow::ensure!(
        openssl::x509::X509::stack_from_pem(&fs::read(trust)?)?
            .iter()
            .any(|c| c.to_der().is_ok_and(|d| d == der)),
        "the provisioning CA must also be in the --ca bundle, so that the certificates it issues are accepted"
    );
    let ec = |nid| -> Result<openssl::pkey::PKey<openssl::pkey::Private>> {
        let group = openssl::ec::EcGroup::from_curve_name(nid)?;
        Ok(openssl::pkey::PKey::from_ec_key(
            openssl::ec::EcKey::generate(&group)?,
        )?)
    };
    let key = match profile.policy().and_then(|p| p.suite_b) {
        Some(tls_profile::SuiteB::MinLos192) => ec(openssl::nid::Nid::SECP384R1)?,
        Some(tls_profile::SuiteB::MinLos128) => ec(openssl::nid::Nid::X9_62_PRIME256V1)?,
        None => openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?,
    };
    provisioning.self_test(&key)?;
    Ok(provisioning)
}
/// Log every provisioning record and the policy entries that conflict with
/// them (docs/re-provision.md#startup-log). Retirement is honoured with or
/// without `--provisioning-ca`.
fn log_provisioning_records(engine: &Engine, policy: &Policy) -> Result<()> {
    let names = policy
        .principals
        .iter()
        .map(|(fingerprint, entry)| (fingerprint.clone(), entry.name.clone()))
        .collect();
    let (records, warnings) = engine.provisioning_records(&names)?;
    for record in records {
        tracing::info!("{record}");
    }
    for warning in warnings {
        tracing::warn!("{warning}");
    }
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    // Restrict newly created database/WAL files without unsafe process-global umask changes.
    let matches = <Args as clap::CommandFactory>::command().get_matches();
    let args =
        <Args as clap::FromArgMatches>::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let ec_curves_chosen = ec_curves_chosen(&matches);
    if let Err(message) = check_combinations(&args.command) {
        <Args as clap::CommandFactory>::command()
            .error(clap::error::ErrorKind::ArgumentConflict, message)
            .exit();
    }
    // FIPS mode is decided before any other OpenSSL use: loading the provider
    // explicitly keeps the default provider from loading as a fallback.
    let host_fips = keytend_kmip_server::fips::host_requires();
    let fips = args.fips || host_fips;
    if host_fips && !args.fips {
        tracing::warn!(
            "the host kernel is in FIPS mode (/proc/sys/crypto/fips_enabled = 1); entering FIPS mode"
        );
    }
    if fips
        && !matches!(
            args.command,
            Command::TlsProfiles | Command::Healthcheck { .. }
        )
    {
        if let Command::Serve(options) = &args.command {
            fips_settings(options)?;
        }
        let status = keytend_kmip_server::fips::load_provider().context("FIPS mode")?;
        if matches!(args.command, Command::FipsCheck) {
            println!("{}", serde_json::to_string_pretty(&status)?);
            return Ok(());
        }
        // load_provider refuses a "fips" provider whose status is not 1.
        let provider = &status.providers[0];
        let reported = |v: &Option<String>| v.clone().unwrap_or_else(|| "not reported".into());
        tracing::info!(library = status.library, providers = ?status.loaded, provider_name = %reported(&provider.name), provider_version = %reported(&provider.version), provider_build_info = %reported(&provider.build_info), provider_status = provider.status.unwrap_or_default(), self_tests = status.self_tests, checks = ?status.checks, "FIPS mode: OpenSSL FIPS provider loaded");
    } else if matches!(args.command, Command::FipsCheck) {
        bail!("fips-check needs --fips, KMIP_FIPS=true or a FIPS-mode host");
    }
    match args.command {
        Command::FipsCheck => unreachable!("handled above"),
        Command::PasswordVerifier => {
            let mut line = Zeroizing::new(String::new());
            std::io::stdin().read_line(&mut line)?;
            let password = line.trim_end_matches(['\r', '\n']);
            let verifier =
                keytend_kmip_server::credentials::PasswordVerifier::new(password.as_bytes())?;
            println!("{}", serde_json::to_string(&verifier)?);
        }
        Command::TlsProfiles => {
            println!(
                "{}",
                serde_json::to_string_pretty(&tls_profile::describe())?
            );
        }
        Command::GenerateMasterKey { output } => {
            let key = keytend_kmip_server::crypto::random(32)?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut f = options.open(&output).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    anyhow::anyhow!("output {} already exists", output.display())
                } else {
                    anyhow::Error::new(e).context(format!("create {}", output.display()))
                }
            })?;
            f.write_all(&key)?;
            f.sync_all()?;
        }
        Command::CheckStore {
            database,
            master_key,
            audit_checkpoint,
        } => {
            if !database.is_file() {
                bail!("database to verify does not exist");
            }
            // No restore or in-place rotation may move the files meanwhile.
            let _read = keytend_kmip_server::maintenance::read_guard(&database)?;
            let master_key = choose_master_key(&database, &master_key)?;
            let store = Store::open_read_only(&database, &master_key)?;
            let verification = store.verify()?;
            if let Some(checkpoint) = audit_checkpoint {
                store.verify_audit_checkpoint(&checkpoint)?;
            }
            println!("Master key, object records and audit chain verified");
            if !verification.object_index_verified {
                println!("{}", older_schema_note(&verification));
            }
        }
        Command::Backup {
            database,
            master_key,
            output,
            output_dir,
            retain,
            if_exists,
        } => {
            if if_exists && database_absent(&database)? {
                println!(
                    "No database at {} yet; nothing to back up",
                    database.display()
                );
                return Ok(());
            }
            if !database.is_file() {
                bail!("database to back up does not exist");
            }
            let master_key = {
                let _read = keytend_kmip_server::maintenance::read_guard(&database)?;
                choose_master_key(&database, &master_key)?
            };
            let (time, verification) = match (output, output_dir) {
                (Some(output), _) => {
                    let time = keytend_kmip_server::store::now();
                    let _read = keytend_kmip_server::maintenance::read_guard(&database)?;
                    let verification =
                        Store::open_read_only(&database, &master_key)?.backup(&output)?;
                    (time, verification)
                }
                (None, Some(dir)) => {
                    let backup = keytend_kmip_server::maintenance::backup_to_directory(
                        &database,
                        &master_key,
                        &dir,
                        retain.map(|n| n as usize),
                    )?;
                    println!(
                        "Backup {} written and verified: {} objects, {} audit entries, {} bytes",
                        backup.path.display(),
                        backup.verification.objects,
                        backup.verification.audit_entries,
                        backup.bytes
                    );
                    if !backup.pruned.is_empty() {
                        println!(
                            "Removed {} older backups: {}",
                            backup.pruned.len(),
                            backup.pruned.join(", ")
                        );
                    }
                    for kept in &backup.kept {
                        println!("Kept {kept}");
                    }
                    if !backup.unrecorded.is_empty() {
                        println!(
                            "{} backup-named files in {} are not recorded as backups of {} and are never removed: {}",
                            backup.unrecorded.len(),
                            dir.display(),
                            database.display(),
                            backup.unrecorded.join(", ")
                        );
                    }
                    (backup.created_unix, backup.verification)
                }
                (None, None) => unreachable!("clap requires --output or --output-dir"),
            };
            if !verification.object_index_verified {
                eprintln!("{}", older_schema_note(&verification));
            }
            if let Err(error) =
                keytend_kmip_server::maintenance::record_last_backup(&database, time)
            {
                eprintln!(
                    "note: the backup time was not recorded in {}: {error:#}",
                    keytend_kmip_server::maintenance::last_backup_path(&database).display()
                );
            }
        }
        Command::RotateMasterKey {
            database,
            master_key,
            new_master_key,
            audit_checkpoint,
            output,
            create_directory,
            in_place,
            previous_master_key,
            checkpoint_output,
            revert,
        } => {
            if in_place {
                let previous_master_key =
                    previous_master_key.context("--in-place needs --previous-master-key")?;
                let rotation = keytend_kmip_server::maintenance::InPlaceRotation {
                    database: &database,
                    master_key: &master_key,
                    previous_master_key: &previous_master_key,
                    audit_checkpoint: audit_checkpoint.as_deref(),
                    checkpoint_output: checkpoint_output.as_deref(),
                };
                let outcome = if revert {
                    keytend_kmip_server::maintenance::revert_in_place(&rotation)?
                } else {
                    keytend_kmip_server::maintenance::rotate_in_place(&rotation)?
                };
                for line in outcome.messages {
                    println!("{line}");
                }
                return Ok(());
            }
            let (Some(new_master_key), Some(output)) = (new_master_key, output) else {
                unreachable!("clap requires --new-master-key and --output without --in-place");
            };
            if !database.is_file() {
                bail!("database to rotate does not exist");
            }
            // The source is opened as serve opens it (an older one is
            // upgraded), so it takes the server's lock.
            let _writer_lock =
                keytend_kmip_server::store::WriterLock::acquire(&database, "rotate-master-key")?;
            if let Some(unfinished) =
                keytend_kmip_server::maintenance::unfinished_maintenance(&database, false)?
            {
                bail!("{unfinished}");
            }
            if create_directory {
                let parent = output
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .ok_or_else(|| anyhow::anyhow!("output has no parent directory to create"))?;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| {
                        if e.kind() == std::io::ErrorKind::AlreadyExists {
                            anyhow::anyhow!(
                                "output directory {} already exists (--create-directory needs a new one)",
                                parent.display()
                            )
                        } else {
                            anyhow::Error::new(e).context(format!("create {}", parent.display()))
                        }
                    })?;
            }
            let summary = Store::open(&database, &master_key)?.rotate_master_key_checked(
                &new_master_key,
                &output,
                audit_checkpoint.as_deref(),
            )?;
            // Cut-over evidence the Job script used to check with a shell: the
            // snapshot opens and verifies only with the new key, and the source
            // still verifies with the old key.
            Store::open(&output, &new_master_key)?.verify_integrity()?;
            if Store::open(&output, &master_key).is_ok_and(|s| s.verify_integrity().is_ok()) {
                bail!("rotated snapshot unexpectedly opens with the old key");
            }
            Store::open(&database, &master_key)?.verify_integrity()?;
            println!(
                "Verified rotated snapshot: {} objects, {} audit entries. Use the new key for this snapshot; retain the old key for old backups.",
                summary.objects, summary.audit_entries
            );
        }
        Command::Restore {
            from,
            id,
            database,
            master_key,
            audit_checkpoint,
        } => {
            let outcome = keytend_kmip_server::maintenance::restore(
                &keytend_kmip_server::maintenance::Restore {
                    from: &from,
                    id: &id,
                    database: &database,
                    master_key: &master_key,
                    audit_checkpoint: audit_checkpoint.as_deref(),
                },
            )?;
            for line in outcome.messages {
                println!("{line}");
            }
        }
        Command::AuditCheckpoint {
            database,
            master_key,
            output,
            previous,
        } => {
            if !database.is_file() {
                bail!("database to checkpoint does not exist");
            }
            let _read = keytend_kmip_server::maintenance::read_guard(&database)?;
            Store::open_read_only(&database, &master_key)?
                .write_audit_checkpoint(&output, previous.as_deref())?;
            println!(
                "Authenticated audit checkpoint exported; retain it independently of database snapshots"
            );
        }
        Command::Healthcheck { address } => {
            timeout(Duration::from_secs(3), async {
                let mut s = TcpStream::connect(address).await?;
                s.write_all(
                    b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .await?;
                let mut response = [0; 64];
                let n = s.read(&mut response).await?;
                if !response[..n].starts_with(b"HTTP/1.1 200") {
                    bail!("not ready");
                }
                Ok::<_, anyhow::Error>(())
            })
            .await??;
        }
        Command::Serve(options) => {
            let ServeOptions {
                listen,
                https_listen,
                https_path,
                health_listen,
                cert,
                key,
                ca,
                crl,
                validation_ca,
                policy,
                users,
                allow_stored_credential_secrets,
                database,
                master_key,
                audit_checkpoint,
                experimental_v3,
                triple_des,
                interop_test_mode,
                tls_profile,
                max_connections,
                max_lease_seconds,
                idle_timeout,
                destroyed_name_reuse,
                lease_states,
                get_attributes_none,
                ec_curves,
                text_encoding,
                metrics: metrics_setting,
                metrics_object_census_interval,
                object_cache_mib,
                object_cache_ttl,
                provisioning_ca,
                provisioning_ca_key,
            } = *options;
            let text_encoding = text_encoding.resolve();
            let idle = idle_limit(idle_timeout);
            // Reported in the readiness line: whether each optional file is set.
            let (users_set, crl_set, validation_ca_set, provisioning_set) = (
                users.is_some(),
                crl.is_some(),
                validation_ca.is_some(),
                provisioning_ca.is_some(),
            );
            let logged_https_path = https_path.clone();
            if fips {
                tracing::info!(tls_profile = %cli_name(&tls_profile), triple_des = %cli_name(&triple_des), "FIPS mode: non-approved services are refused and not advertised (docs/fips.md)");
            }
            if fips && ec_curves_chosen && ec_curves == EcCurves::Extended {
                tracing::info!(
                    "--ec-curves extended has no effect in FIPS mode: only P-224, P-256, P-384 and P-521 are offered"
                );
            }
            if interop_test_mode {
                tracing::warn!(
                    "interop test mode: the KMIP Interop operation is offered; it SHALL NOT be available in a production server"
                );
            }
            let policy = Arc::new(read_policy(&policy)?);
            let acceptor = Arc::new(
                tls(&cert, &key, &ca, crl.as_deref(), tls_profile)
                    .with_context(|| format!("TLS profile {tls_profile:?}"))?,
            );
            if let Some(warning) = tls_profile.policy().and_then(|p| p.warning) {
                tracing::warn!(tls_profile = ?tls_profile, "{warning}");
            }
            let mut provisioning = match (&provisioning_ca, &provisioning_ca_key) {
                (Some(ca_file), Some(key_file)) => Some(
                    provisioning(
                        ca_file,
                        key_file,
                        &cert,
                        &ca,
                        crl.as_deref(),
                        tls_profile,
                        fips,
                        &policy,
                    )
                    .context("--provisioning-ca")?,
                ),
                _ => None,
            };
            if provisioning.is_some() {
                tracing::warn!(
                    "Re-Provision is offered: a client can replace its own certificate with one the provisioning CA issues, and its old certificate is refused from then on (docs/re-provision.md)"
                );
            }
            // The data directory must be provisioned with mode 0700 (or a restricted pod fsGroup).
            if database
                .parent()
                .is_some_and(|parent| !parent.as_os_str().is_empty() && !parent.is_dir())
            {
                bail!("database directory does not exist");
            }
            let certificate_validation = match validation_ca {
                Some(path) => {
                    let mut file = fs::File::open(path)?;
                    let mut bytes = vec![];
                    std::io::Read::read_to_end(
                        &mut std::io::Read::take(
                            &mut file,
                            (keytend_kmip_server::certificates::MAX_BYTES + 1) as u64,
                        ),
                        &mut bytes,
                    )?;
                    keytend_kmip_server::certificates::CertificateValidation::from_pem(&bytes)?
                }
                None => keytend_kmip_server::certificates::CertificateValidation::default(),
            };
            // Held until the process exits: restore and in-place rotation
            // refuse to replace the database while it is held.
            let _writer_lock = keytend_kmip_server::store::WriterLock::acquire(&database, "serve")?;
            // Store::open creates a missing database: never while a restore or
            // an in-place rotation has the real one moved aside.
            if let Some(unfinished) =
                keytend_kmip_server::maintenance::unfinished_maintenance(&database, false)?
            {
                bail!("{unfinished}");
            }
            if audit_checkpoint.is_some() && !database.is_file() {
                bail!("database required by the audit checkpoint does not exist");
            }
            let store = Store::open(&database, &master_key)?;
            store.set_object_cache(keytend_kmip_server::store::CacheLimits {
                max_bytes: (object_cache_mib as usize) << 20,
                idle: Duration::from_secs(object_cache_ttl),
            });
            let store_verified_at = std::time::SystemTime::now();
            let audit_checkpoint_verified = audit_checkpoint.is_some();
            if let Some(checkpoint) = audit_checkpoint {
                store.verify_audit_checkpoint(&checkpoint)?;
            }
            let registry = Arc::new(keytend_kmip_server::metrics::Registry::new());
            let credentials = match &users {
                Some(path) => read_users(path, &policy, allow_stored_credential_secrets)?,
                None => Credentials::default(),
            };
            let legacy = credentials.legacy_verifiers();
            if legacy > 0 {
                if fips {
                    tracing::warn!(
                        legacy,
                        "users-file scrypt verifiers cannot authenticate in FIPS mode; re-provision them with `keytend-kmip-server password-verifier`"
                    );
                } else {
                    tracing::info!(
                        legacy,
                        "users file holds legacy scrypt verifiers; they still verify, but not in FIPS mode"
                    );
                }
            }
            let (subscriptions, endpoints) = server_to_client(&policy)?;
            let mut delivery_error = None;
            let mut users_error = None;
            let mut reverse = None;
            let engine = Arc::new_cyclic(|weak| {
                let mut engine = Engine::new(store, experimental_v3)
                    .with_certificate_validation(certificate_validation)
                    .with_triple_des(triple_des)
                    .with_interop_test_mode(interop_test_mode)
                    .with_fips(fips)
                    .with_maximum_lease(max_lease_seconds)
                    .with_destroyed_name_reuse(destroyed_name_reuse)
                    .with_lease_states(lease_states)
                    .with_get_attributes_none(get_attributes_none)
                    .with_ec_curves(ec_curves)
                    .with_text_encoding(text_encoding)
                    .with_metrics(registry.clone());
                if let Some(provisioning) = provisioning.take() {
                    engine = engine.with_provisioning(provisioning);
                }
                for (principal, users) in credentials.users {
                    if let Err(error) = engine.add_policy_users(&principal, users) {
                        users_error = Some(error);
                    }
                }
                for (principal, devices) in credentials.devices {
                    if let Err(error) = engine.add_policy_devices(&principal, devices) {
                        users_error = Some(error);
                    }
                }
                for principal in policy.principals.values() {
                    if principal.client_identity == ClientIdentity::Credential {
                        engine.use_credential_identity(&principal.name);
                    }
                }
                if !subscriptions.is_empty() {
                    let (sink, handle) = keytend_kmip_server::delivery::start(
                        endpoints,
                        keytend_kmip_server::delivery::Limits::default(),
                        delivery_report(weak.clone()),
                    );
                    reverse = Some(handle);
                    match keytend_kmip_server::protocol::ServerToClient::new(subscriptions, sink) {
                        Ok(delivery) => engine = engine.with_server_to_client(delivery),
                        Err(error) => delivery_error = Some(error),
                    }
                }
                Mutex::new(engine)
            });
            if let Some(error) = users_error {
                return Err(error);
            }
            if let Some(error) = delivery_error {
                bail!("invalid client endpoint configuration: {error}");
            }
            {
                let engine = engine
                    .lock()
                    .map_err(|_| anyhow::anyhow!("storage mutex poisoned"))?;
                log_provisioning_records(&engine, &policy)?;
                // An unreadable server-wide record fails the operations that
                // use it closed; name it now rather than at the first request
                // (docs/defaults-and-constraints.md).
                if let Err(error) = engine.check_server_records() {
                    tracing::error!(%error, "server-wide settings are unreadable; affected requests fail until an empty Set Defaults or Set Constraints replaces them");
                }
            }
            let health = TcpListener::bind(health_listen).await?;
            let listener = TcpListener::bind(listen).await?;
            let https_listener = match https_listen {
                Some(address) => Some(TcpListener::bind(address).await?),
                None => None,
            };
            anyhow::ensure!(
                https_path.starts_with('/')
                    && !https_path
                        .chars()
                        .any(|c| c.is_control() || matches!(c, '?' | '#')),
                "HTTPS path must be an absolute URI path"
            );
            let http_config = server_http::Config::new(https_path, text_encoding, idle);
            let stream_engine = engine.clone();
            tokio::spawn(async move {
                let mut cleanup = tokio::time::interval(Duration::from_secs(30));
                loop {
                    cleanup.tick().await;
                    let engine = stream_engine.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        if let Ok(mut engine) = engine.lock() {
                            engine.expire_multipart();
                            // Idle cached objects leave memory even when no
                            // request arrives.
                            engine.store.expire_object_cache();
                        }
                    })
                    .await;
                }
            });
            // Deferred asynchronous requests run here, one batch per tick, so a
            // queued batch holds the engine no longer than a synchronous one.
            let async_engine = engine.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_millis(50));
                loop {
                    tick.tick().await;
                    let engine = async_engine.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        if let Ok(mut engine) = engine.lock()
                            && engine.asynchronous_pending()
                        {
                            engine.run_asynchronous();
                        }
                    })
                    .await;
                }
            });
            let metrics = Arc::new(network::Metrics::new(max_connections));
            let health_metrics = metrics.clone();
            let health_engine = engine.clone();
            let endpoint = (metrics_setting == metrics_endpoint::MetricsSetting::On).then(|| {
                if metrics_object_census_interval > 0 {
                    tokio::spawn(metrics_endpoint::census_loop(
                        engine.clone(),
                        registry.clone(),
                        metrics_object_census_interval,
                    ));
                }
                Arc::new(metrics_endpoint::Endpoint::new(
                    metrics_endpoint::Info {
                        fips,
                        max_lease_seconds,
                        census_interval: metrics_object_census_interval,
                        audit_checkpoint_verified,
                        store_verified_at,
                        database: database.clone(),
                    },
                    registry.clone(),
                    metrics.clone(),
                    engine.clone(),
                ))
            });
            tokio::spawn(async move {
                health_server(health, health_engine, health_metrics, endpoint).await
            });
            let limit = Arc::new(Semaphore::new(max_connections as usize));
            let mut tasks = tokio::task::JoinSet::new();
            tracing::info!(version=env!("CARGO_PKG_VERSION"),%listen,https_listen=%https_listen.map_or_else(|| "off".to_string(), |a| a.to_string()),%health_listen,experimental_v3,fips,triple_des=%cli_name(&triple_des),tls_profile=%cli_name(&tls_profile),idle_timeout,destroyed_name_reuse=%cli_name(&destroyed_name_reuse),lease_states=%cli_name(&lease_states),get_attributes_none=%cli_name(&get_attributes_none),ec_curves=%cli_name(&keytend_kmip_server::crypto::ec::effective(ec_curves, fips)),text_encoding=%text_encoding_label(&text_encoding),metrics=%cli_name(&metrics_setting),metrics_object_census_interval,object_cache_mib,object_cache_ttl,max_connections,max_lease_seconds,https_path=%logged_https_path,interop_test_mode,allow_stored_credential_secrets,users=users_set,crl=crl_set,validation_ca=validation_ca_set,provisioning=provisioning_set,audit_checkpoint=audit_checkpoint_verified,"KMIP listener ready");
            let shutdown = async {
                #[cfg(unix)]
                {
                    let mut term =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .expect("install SIGTERM handler");
                    tokio::select! {_ = tokio::signal::ctrl_c()=>{},_ = term.recv()=>{}}
                }
                #[cfg(not(unix))]
                {
                    let _ = tokio::signal::ctrl_c().await;
                }
            };
            tokio::pin!(shutdown);
            let mut metric_interval = tokio::time::interval(Duration::from_secs(30));
            metric_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            'serving: loop {
                // Reap completed tasks before another accept, so even a ready
                // backlog cannot accumulate an unbounded completed-task set.
                while let Some(result) = tasks.try_join_next() {
                    if let Err(error) = result {
                        tracing::error!(%error, "Connection task panicked");
                    }
                }
                // Pin one admission/accept future across task completions and log ticks.
                // Cancelling it on each completion would inflate wait accounting.
                let accepted = network::accept(
                    &listener,
                    https_listener.as_ref(),
                    limit.clone(),
                    metrics.clone(),
                );
                tokio::pin!(accepted);
                let accepted = loop {
                    tokio::select! {
                        _=&mut shutdown=>break 'serving,
                        Some(result)=tasks.join_next()=>{if let Err(e)=result{tracing::error!(error=%e,"Connection task panicked");}},
                        _=metric_interval.tick()=>tracing::info!(phase="periodic",counters=%metrics.snapshot(),"Connection lifecycle counters"),
                        accepted=&mut accepted=>break accepted?,
                    }
                };
                let network::Accepted {
                    socket,
                    https,
                    mut lifecycle,
                } = accepted;
                let acceptor = acceptor.clone();
                let engine = engine.clone();
                let policy = policy.clone();
                let reverse = reverse.clone();
                let config = if https {
                    Some(http_config.clone())
                } else {
                    None
                };
                // Every wait inside a connection has its own deadline (idle,
                // handshake, frame, header, body, write); there is no overall
                // lifetime limit, so an active connection is never cut.
                tasks.spawn(async move {
                    let result = connection(
                        socket,
                        acceptor,
                        engine,
                        policy,
                        reverse,
                        config,
                        idle,
                        &mut lifecycle,
                    )
                    .await;
                    lifecycle.finish(result.is_err(), false);
                });
            }
            drop(listener);
            drop(https_listener);
            tracing::info!("Draining connections");
            let drain = async { while tasks.join_next().await.is_some() {} };
            if timeout(Duration::from_secs(20), drain).await.is_err() {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
            }
            tracing::info!(phase="shutdown",counters=%metrics.snapshot(),"Connection lifecycle counters");
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn connection(
    socket: TcpStream,
    acceptor: Arc<SslAcceptor>,
    engine: Arc<Mutex<Engine>>,
    policy: Arc<Policy>,
    reverse: Option<keytend_kmip_server::delivery::Reverse>,
    http: Option<server_http::Config>,
    idle: Option<Duration>,
    lifecycle: &mut network::Lifecycle,
) -> Result<()> {
    socket.set_nodelay(true)?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, socket)?;
    lifecycle.tls_started();
    let handshake = timeout(Duration::from_secs(10), Pin::new(&mut stream).accept()).await;
    match &handshake {
        Ok(Ok(())) => lifecycle.tls_finished(None),
        Ok(Err(error)) => lifecycle.tls_finished(Some(network::tls_failure_reason(error))),
        Err(_) => lifecycle.tls_timed_out(),
    }
    handshake.context("TLS handshake timeout")??;
    let cert = stream
        .ssl()
        .peer_certificate()
        .context("client certificate required")?;
    let fingerprint = hex::encode(cert.digest(MessageDigest::sha256())?);
    // The store's word on this certificate (a Re-Provision may have retired
    // or replaced it), read off the async worker like every engine lock. If
    // the store cannot answer (an integrity failure, for example), the policy
    // alone must not admit the certificate: the request is answered with
    // General Failure, as an operation on that store would be.
    let lookup = {
        let engine = engine.clone();
        let fingerprint = fingerprint.clone();
        tokio::task::spawn_blocking(move || -> Result<Lookup> {
            engine
                .lock()
                .map_err(|_| anyhow::anyhow!("storage mutex poisoned"))?
                .provisioned_lookup(&fingerprint)
        })
        .await?
    };
    let lookup = match lookup {
        Ok(lookup) => lookup,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "KMIP internal operation failed");
            match http {
                Some(config) => {
                    server_http::serve(stream, engine, None, cert, config, Refusal::StoreFailure)
                        .await?
                }
                None => refuse(&mut stream, engine, Refusal::StoreFailure).await?,
            }
            bail!("the store could not check the certificate");
        }
    };
    let Some((owner, policy_fingerprint)) = resolve_principal(&policy, &lookup, &fingerprint)
    else {
        lifecycle.unlisted();
        match http {
            // The same Permission Denied answer as the binary listener, in a
            // KMIP response over HTTP (server_http.rs).
            Some(config) => {
                server_http::serve(stream, engine, None, cert, config, Refusal::Unlisted).await?
            }
            None => refuse(&mut stream, engine, Refusal::Unlisted).await?,
        }
        bail!("certificate is not authorized");
    };
    let leaf = cert.to_der()?;
    let chain = match stream.ssl().peer_cert_chain() {
        Some(chain) => chain
            .iter()
            .map(|c| c.to_der())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|der| *der != leaf)
            .collect(),
        None => vec![],
    };
    let channel = Channel {
        fingerprint,
        policy_fingerprint,
        certificate: leaf,
        chain,
    };
    if let Some(config) = http {
        let result = server_http::serve(
            stream,
            engine,
            Some((owner, channel)),
            cert,
            config,
            Refusal::Unlisted,
        )
        .await;
        if result.as_ref().is_err_and(server_http::idle_timed_out) {
            lifecycle.idle_timeout();
        }
        return result;
    }
    loop {
        let mut header = [0; 8];
        let read = stream.read_exact(&mut header);
        let read = match idle {
            Some(limit) => timeout(limit, read).await,
            None => Ok(read.await),
        };
        match read {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                lifecycle.idle_timeout();
                bail!("idle timeout");
            }
        }
        if cert
            .not_after()
            .compare(Asn1Time::days_from_now(0)?.as_ref())?
            .is_lt()
        {
            bail!("client certificate expired");
        }
        let len = ttlv::frame_length(&header)?;
        let mut data = Zeroizing::new(vec![0; len]);
        data[..8].copy_from_slice(&header);
        timeout(Duration::from_secs(10), stream.read_exact(&mut data[8..]))
            .await
            .context("frame timeout")??;
        let response = match ttlv::decode(&data) {
            Ok(request) => {
                let e = engine.clone();
                let principal = owner.clone();
                let channel = channel.clone();
                tokio::task::spawn_blocking(move || -> Result<_> {
                    // Header-credential verifier derivations run without the
                    // engine lock; verification then reuses their outputs.
                    let work = e
                        .lock()
                        .map_err(|_| anyhow::anyhow!("storage mutex poisoned"))?
                        .credential_work(&principal.name, &request, Some(&principal.operations));
                    let derivations = work.run();
                    let mut engine = e
                        .lock()
                        .map_err(|_| anyhow::anyhow!("storage mutex poisoned"))?;
                    // This one TTLV channel can be reversed (endpoint_role.rs).
                    derivations
                        .scope(|| {
                            engine.with_channel(&channel, |engine| {
                                engine.process_reversible(
                                    &principal.name,
                                    &request,
                                    Some(&principal.operations),
                                    &principal.object_grants,
                                )
                            })
                        })
                        .map_err(|f| anyhow::anyhow!(f.message))
                })
                .await??
            }
            Err(_) => error_response(Version(1, 4), Failure::new(4, "Malformed TTLV request")),
        };
        let bytes = Zeroizing::new(response.encode());
        timeout(Duration::from_secs(10), stream.write_all(&bytes)).await??;
        lifecycle.response_written();
        // Set Endpoint Role accepted the client role: the server is now the
        // client on this channel until it hands the roles back.
        if keytend_kmip_server::protocol::reversal_accepted(&response) {
            let reverse = reverse
                .as_ref()
                .filter(|r| r.configured(&owner.name))
                .context("role reversal without a configured client endpoint")?;
            reverse.serve(&owner.name, &mut stream).await?;
        }
    }
}
/// A CA-valid certificate without a policy entry gets one versioned KMIP answer, Permission
/// Denied for every batch item (KMIP 1.4 section 11.1: a client not allowed to perform the
/// operation), and the connection is then closed. Without it, clients only see a connection
/// reset, which they must treat as a transient network failure and retry. The wait for that
/// one request stays a fixed 30 s whatever `--idle-timeout` says: the peer has no session.
/// Why a connection without a principal is refused: its certificate is not
/// listed (every item Permission Denied), or the store could not check it
/// (General Failure).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Unlisted,
    StoreFailure,
}
async fn refuse(
    stream: &mut SslStream<TcpStream>,
    engine: Arc<Mutex<Engine>>,
    refusal: Refusal,
) -> Result<()> {
    let mut header = [0; 8];
    timeout(Duration::from_secs(30), stream.read_exact(&mut header))
        .await
        .context("idle timeout")??;
    let len = ttlv::frame_length(&header)?;
    let mut data = Zeroizing::new(vec![0; len]);
    data[..8].copy_from_slice(&header);
    timeout(Duration::from_secs(10), stream.read_exact(&mut data[8..]))
        .await
        .context("frame timeout")??;
    let response = match ttlv::decode(&data) {
        Ok(request) if refusal == Refusal::StoreFailure => store_failure_response(&request),
        Ok(request) => {
            tokio::task::spawn_blocking(move || -> Result<_> {
                let mut engine = engine
                    .lock()
                    .map_err(|_| anyhow::anyhow!("storage mutex poisoned"))?;
                // No permitted operation, so no item reaches identifiers, objects or the store.
                engine
                    .process_with_grants(UNLISTED_OWNER, &request, Some(&[]), &[])
                    .map_err(|f| anyhow::anyhow!(f.message))
            })
            .await??
        }
        Err(_) => error_response(Version(1, 4), Failure::new(4, "Malformed TTLV request")),
    };
    let bytes = Zeroizing::new(response.encode());
    timeout(Duration::from_secs(10), stream.write_all(&bytes)).await??;
    let _ = timeout(Duration::from_secs(2), stream.shutdown()).await;
    Ok(())
}
/// Policy names cannot contain NUL, so this owner never matches a configured principal.
const UNLISTED_OWNER: &str = "\0unlisted";
async fn health_server(
    listener: TcpListener,
    engine: Arc<Mutex<Engine>>,
    metrics: Arc<network::Metrics>,
    endpoint: Option<Arc<metrics_endpoint::Endpoint>>,
) {
    let permits = Arc::new(Semaphore::new(16));
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let engine = engine.clone();
        let metrics = metrics.clone();
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut buf = [0; 1024];
            if let Ok(Ok(n)) = timeout(Duration::from_secs(2), socket.read(&mut buf)).await {
                let prometheus = endpoint.as_ref().filter(|_| {
                    buf[..n].starts_with(b"GET /metrics ") || buf[..n].starts_with(b"GET /metrics?")
                });
                let (status, body) = if buf[..n].starts_with(b"GET /livez ") {
                    ("200 OK", "alive\n".to_owned())
                } else if let Some(endpoint) = prometheus {
                    ("200 OK", endpoint.render().await)
                } else if buf[..n].starts_with(b"GET /connection-metrics ") {
                    ("200 OK", metrics.snapshot().to_string() + "\n")
                } else if buf[..n].starts_with(b"GET /readyz ") {
                    let ok = tokio::task::spawn_blocking(move || {
                        engine.lock().map(|e| e.store.healthy()).unwrap_or(false)
                    })
                    .await
                    .unwrap_or(false);
                    if ok {
                        ("200 OK", "ready\n".to_owned())
                    } else {
                        ("503 Service Unavailable", "unavailable\n".to_owned())
                    }
                } else {
                    ("404 Not Found", "not found\n".to_owned())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    if prometheus.is_some() {
                        keytend_kmip_server::metrics::CONTENT_TYPE
                    } else if buf[..n].starts_with(b"GET /connection-metrics ") {
                        "application/json"
                    } else {
                        "text/plain"
                    },
                    body.len()
                );
                let _ = timeout(
                    Duration::from_secs(2),
                    socket.write_all(response.as_bytes()),
                )
                .await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    //! Transport clauses checked against the production acceptor built by `tls`.
    use super::*;
    use openssl::{
        asn1::Asn1Integer,
        bn::BigNum,
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::{PKey, Private},
        rsa::Rsa,
        ssl::SslConnector,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        },
    };
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
    };

    pub(crate) struct Identity {
        pub(crate) cert: X509,
        pub(crate) key: PKey<Private>,
    }
    pub(crate) fn issue(name: &str, issuer: Option<&Identity>, usage: &str) -> Identity {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        issue_with(name, issuer, usage, key, MessageDigest::sha256())
    }
    pub(crate) fn issue_key(
        key: PKey<Private>,
        name: &str,
        issuer: Option<&Identity>,
        usage: &str,
        digest: MessageDigest,
    ) -> Identity {
        issue_with(name, issuer, usage, key, digest)
    }
    /// A test certificate with the given key, signed with `digest` by `issuer` (or self-signed).
    pub(crate) fn issue_with(
        name: &str,
        issuer: Option<&Identity>,
        usage: &str,
        key: PKey<Private>,
        digest: MessageDigest,
    ) -> Identity {
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(rand_serial()).unwrap();
        b.set_serial_number(&Asn1Integer::from_bn(&serial).unwrap())
            .unwrap();
        b.set_subject_name(&subject).unwrap();
        b.set_issuer_name(issuer.map_or(&subject, |i| i.cert.subject_name()))
            .unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        match usage {
            "ca" => b
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap(),
            "server" => {
                let san = SubjectAlternativeName::new()
                    .dns("localhost")
                    .build(&b.x509v3_context(issuer.map(|i| &*i.cert), None))
                    .unwrap();
                b.append_extension(san).unwrap();
                b.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
                    .unwrap();
            }
            _ => b
                .append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
                .unwrap(),
        }
        if usage != "ca" && key.ec_key().is_ok() {
            // Suite B (RFC 5759) end-entity certificates carry digitalSignature.
            b.append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        }
        let signer = issuer.map_or(&key, |i| &i.key);
        b.sign(signer, digest).unwrap();
        Identity {
            cert: b.build(),
            key,
        }
    }
    fn rand_serial() -> u32 {
        u32::from_be_bytes(
            keytend_kmip_server::crypto::random(4).unwrap()[..4]
                .try_into()
                .unwrap(),
        ) >> 1
    }
    struct Pki {
        dir: tempfile::TempDir,
        client: Identity,
        foreign: Identity,
    }
    fn pki() -> Pki {
        let dir = tempfile::tempdir().unwrap();
        let ca = issue("test ca", None, "ca");
        let server = issue("localhost", Some(&ca), "server");
        let client = issue("client", Some(&ca), "client");
        let other_ca = issue("foreign ca", None, "ca");
        let foreign = issue("foreign", Some(&other_ca), "client");
        fs::write(dir.path().join("ca.pem"), ca.cert.to_pem().unwrap()).unwrap();
        fs::write(dir.path().join("server.pem"), server.cert.to_pem().unwrap()).unwrap();
        fs::write(
            dir.path().join("server.key"),
            server.key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        Pki {
            dir,
            client,
            foreign,
        }
    }
    #[derive(Default)]
    struct Client<'a> {
        version: Option<SslVersion>,
        suite: Option<&'a str>,
        identity: Option<&'a Identity>,
        legacy: bool,
        hostname: Option<&'a str>,
    }
    /// One connection: the server result (negotiated suite or handshake error)
    /// and whether the client received the server's application reply.
    fn handshake(pki: &Pki, c: Client) -> (Result<(SslVersion, String), String>, bool) {
        let d = pki.dir.path();
        let acceptor = tls(
            &d.join("server.pem"),
            &d.join("server.key"),
            &d.join("ca.pem"),
            None,
            tls_profile::TlsProfile::Modern,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            match acceptor.accept(socket) {
                Ok(mut s) => {
                    let _ = s.write_all(b"ok");
                    let _ = s.flush();
                    let mut b = [0; 1];
                    let _ = s.read(&mut b);
                    let cipher = s.ssl().current_cipher().unwrap();
                    Ok((
                        s.ssl().version2().unwrap(),
                        cipher.standard_name().unwrap_or(cipher.name()).to_owned(),
                    ))
                }
                Err(e) => Err(e.to_string()),
            }
        });
        let mut b = SslConnector::builder(SslMethod::tls_client()).unwrap();
        b.set_ca_file(d.join("ca.pem")).unwrap();
        if c.legacy {
            // Client-side only, so the server is what refuses the old protocol
            // or the weak certificate; before the certificate, which OpenSSL
            // otherwise refuses to load.
            b.set_cipher_list("DEFAULT:@SECLEVEL=0").unwrap();
        }
        if let Some(id) = c.identity {
            b.set_certificate(&id.cert).unwrap();
            b.set_private_key(&id.key).unwrap();
        }
        if let Some(v) = c.version {
            b.set_min_proto_version(Some(v)).unwrap();
            b.set_max_proto_version(Some(v)).unwrap();
        }
        if let Some(suite) = c.suite {
            if c.version == Some(SslVersion::TLS1_3) {
                b.set_ciphersuites(suite).unwrap();
            } else {
                b.set_cipher_list(suite).unwrap();
            }
        }
        let connector = b.build();
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let replied = match connector.connect(c.hostname.unwrap_or("localhost"), socket) {
            Ok(mut s) => {
                let mut b = [0; 2];
                let ok = s.read_exact(&mut b).is_ok() && &b == b"ok";
                let _ = s.write_all(b"x");
                ok
            }
            Err(_) => false,
        };
        (server.join().unwrap(), replied)
    }
    fn mutual(pki: &Pki) -> Client<'_> {
        Client {
            identity: Some(&pki.client),
            ..Client::default()
        }
    }

    // REQ:fdf24bcae6f0a1e9 1.0: the TCP listener speaks TLS 1.0 or later (here TLS 1.2 and 1.3)
    // REQ:4ffab532f047b480 1.1 TLS 1.2 suite: TLS 1.2 is supported
    // REQ:dcc916e52ff5bdee 1.2-1.4 TLS 1.2 and Suite B suites: TLS 1.2 is supported
    // REQ:230e28ec7ddba6f7 2.x Basic: TLS 1.3 is supported
    // REQ:4485f8659f067647 2.x Quantum Safe server: TLS 1.3 is supported
    // REQ:142941e3366030c3 2.x Basic: with TLS 1.3, both CHACHA20-POLY1305 and AES-256-GCM negotiate
    // REQ:3d63e287f3f78f2b 1.2-2.1: SSL, TLS 1.0 and TLS 1.1 are refused by the server
    // REQ:449dab27deea74d4 1.1: no SSL version is accepted
    #[test]
    fn tls_listener_offers_tls_1_2_and_1_3_and_refuses_older_protocols() {
        let pki = pki();
        for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
            let (server, replied) = handshake(
                &pki,
                Client {
                    version: Some(version),
                    ..mutual(&pki)
                },
            );
            assert_eq!(server.unwrap().0, version);
            assert!(replied);
        }
        for suite in ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"] {
            let (server, replied) = handshake(
                &pki,
                Client {
                    version: Some(SslVersion::TLS1_3),
                    suite: Some(suite),
                    ..mutual(&pki)
                },
            );
            assert_eq!(server.unwrap(), (SslVersion::TLS1_3, suite.to_owned()));
            assert!(replied);
        }
        // The default policy is FIPS-approved: no ChaCha20-Poly1305
        // (docs/fips.md; `mozilla-intermediate` keeps it).
        let (server, replied) = handshake(
            &pki,
            Client {
                version: Some(SslVersion::TLS1_3),
                suite: Some("TLS_CHACHA20_POLY1305_SHA256"),
                ..mutual(&pki)
            },
        );
        assert!(server.unwrap_err().contains("no shared cipher"));
        assert!(!replied);
        for version in [SslVersion::TLS1, SslVersion::TLS1_1] {
            let (server, replied) = handshake(
                &pki,
                Client {
                    version: Some(version),
                    legacy: true,
                    ..mutual(&pki)
                },
            );
            let error = server.unwrap_err();
            assert!(
                error.contains("unsupported protocol") || error.contains("version too low"),
                "{error}"
            );
            assert!(!replied);
        }
    }

    // REQ:8975a335a2abceb0 1.0: KMIP traffic is only accepted inside an authenticated, encrypted TLS channel
    // REQ:4c935f9e93051ee3 the channel negotiates an AEAD suite (confidentiality and integrity); plaintext is refused
    // REQ:9a2bc0832eee6c4f clients can verify the server certificate chain and name
    // REQ:34889d4a142740ef 1.1: the server requires a mutually authenticated TLS connection
    // REQ:bcc0d5b18d297469 1.2 TLS 1.2 suite: the server requires a mutually authenticated TLS connection
    // REQ:2e972038ffef1d08 1.3/1.4 Suite B: connections are mutually authenticated TLS
    // REQ:3eac067cd138592b 1.2 Basic: the server only negotiates a secure TLS connection
    // REQ:2cc3eb220a7c967a 1.3-2.1 Basic: the server uses TLS for the channel
    // REQ:a5e8c8556fb0a510 1.1: the channel keeps confidentiality and integrity (AEAD TLS only; plaintext refused)
    // REQ:e22aebcbd1c1347c 1.2: the channel keeps confidentiality and integrity (AEAD TLS only; plaintext refused)
    // REQ:719a1b8645244efd 1.1: the server proves its identity and requires the client's (mutual TLS)
    // REQ:996cb0cab691d92a 1.2: the server proves its identity and requires the client's (mutual TLS)
    #[test]
    fn default_profile_refuses_sha1_signatures_and_weak_keys() {
        // NIST SP 800-131A: SHA-1 certificate signatures and keys below
        // 112-bit strength are refused under every TLS profile, not only
        // the legacy ones.
        let pki = pki();
        let d = pki.dir.path();
        // pki() keeps no CA key, so these cases use a CA of their own.
        let ca_key = issue("strength test ca", None, "ca");
        fs::write(d.join("ca.pem"), ca_key.cert.to_pem().unwrap()).unwrap();
        let server = issue("localhost", Some(&ca_key), "server");
        fs::write(d.join("server.pem"), server.cert.to_pem().unwrap()).unwrap();
        fs::write(
            d.join("server.key"),
            server.key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        let good = issue("client", Some(&ca_key), "client");
        let sha1 = issue_key(
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            "sha1 client",
            Some(&ca_key),
            "client",
            MessageDigest::sha1(),
        );
        let small = issue_key(
            PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap(),
            "rsa1024 client",
            Some(&ca_key),
            "client",
            MessageDigest::sha256(),
        );
        // The image's OpenSSL accepts these at its default security level,
        // so the server's own check is what refuses them there.
        assert!(tls_profile::certificate_strength(&good.cert).is_ok());
        assert!(tls_profile::certificate_strength(&sha1.cert).is_err());
        assert!(tls_profile::certificate_strength(&small.cert).is_err());
        let (server_result, replied) = handshake(
            &pki,
            Client {
                identity: Some(&good),
                ..Client::default()
            },
        );
        assert!(server_result.is_ok() && replied, "{server_result:?}");
        for weak in [&sha1, &small] {
            let (server_result, replied) = handshake(
                &pki,
                Client {
                    identity: Some(weak),
                    legacy: true,
                    ..Client::default()
                },
            );
            assert!(server_result.is_err(), "{server_result:?}");
            assert!(!replied);
        }
        // A SHA-1-signed server certificate stops the listener from starting.
        let weak_server = issue_key(
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            "localhost",
            Some(&ca_key),
            "server",
            MessageDigest::sha1(),
        );
        fs::write(d.join("server.pem"), weak_server.cert.to_pem().unwrap()).unwrap();
        fs::write(
            d.join("server.key"),
            weak_server.key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        let error = tls(
            &d.join("server.pem"),
            &d.join("server.key"),
            &d.join("ca.pem"),
            None,
            tls_profile::TlsProfile::Modern,
        )
        .err()
        .expect("SHA-1 server certificate accepted");
        assert!(error.to_string().contains("weak digest"), "{error:#}");
    }

    #[test]
    fn tls_listener_requires_client_certificates_and_never_accepts_plaintext() {
        let pki = pki();
        for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
            let (server, _) = handshake(
                &pki,
                Client {
                    version: Some(version),
                    ..mutual(&pki)
                },
            );
            let suite = server.unwrap().1;
            assert!(
                suite.contains("GCM") || suite.contains("CHACHA20"),
                "{suite}"
            );
            for identity in [None, Some(&pki.foreign)] {
                let (server, replied) = handshake(
                    &pki,
                    Client {
                        version: Some(version),
                        identity,
                        ..Client::default()
                    },
                );
                assert!(server.is_err());
                assert!(!replied);
            }
            // The client's check of the server name fails for another name.
            let (_, replied) = handshake(
                &pki,
                Client {
                    version: Some(version),
                    hostname: Some("wrong.invalid"),
                    ..mutual(&pki)
                },
            );
            assert!(!replied);
        }
        // A plaintext KMIP request is not a TLS ClientHello and is refused.
        let d = pki.dir.path();
        let acceptor = tls(
            &d.join("server.pem"),
            &d.join("server.key"),
            &d.join("ca.pem"),
            None,
            tls_profile::TlsProfile::Modern,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            acceptor.accept(socket).map(drop).map_err(|e| e.to_string())
        });
        let mut socket = TcpStream::connect(address).unwrap();
        let query = hex::decode("42007801000000384200770100000030420069010000002042006a0200000004000000010000000042006b02000000040000000400000000").unwrap();
        socket.write_all(&query).unwrap();
        assert!(server.join().unwrap().is_err());
    }

    /// The coarse `kmip_tls_handshake_failures_total` reason of one server
    /// handshake with the production acceptor, driven by `client`.
    fn failure_reason(pki: &Pki, client: impl FnOnce(TcpStream) + Send + 'static) -> &'static str {
        let d = pki.dir.path();
        let acceptor = tls(
            &d.join("server.pem"),
            &d.join("server.key"),
            &d.join("ca.pem"),
            None,
            tls_profile::TlsProfile::Modern,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let socket = TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            client(socket)
        });
        let (socket, _) = listener.accept().unwrap();
        let reason = match acceptor.accept(socket) {
            Ok(_) => "succeeded",
            Err(openssl::ssl::HandshakeError::Failure(mid)) => {
                network::TLS_FAILURE_REASONS[network::tls_failure_reason(mid.error())]
            }
            Err(e) => panic!("unexpected handshake error {e}"),
        };
        client.join().unwrap();
        reason
    }

    fn connector(pki: &Pki, identity: Option<&Identity>, ca: bool) -> SslConnector {
        let mut b = SslConnector::builder(SslMethod::tls_client()).unwrap();
        if ca {
            b.set_ca_file(pki.dir.path().join("ca.pem")).unwrap();
        }
        if let Some(id) = identity {
            b.set_certificate(&id.cert).unwrap();
            b.set_private_key(&id.key).unwrap();
        }
        b.build()
    }

    #[test]
    fn tls_handshake_failures_are_classified_by_coarse_reason() {
        let pki = pki();
        let ok = connector(&pki, Some(&pki.client), true);
        assert_eq!(
            failure_reason(&pki, move |s| {
                let _ = ok.connect("localhost", s);
            }),
            "succeeded"
        );
        for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
            let mut b = SslConnector::builder(SslMethod::tls_client()).unwrap();
            b.set_ca_file(pki.dir.path().join("ca.pem")).unwrap();
            b.set_min_proto_version(Some(version)).unwrap();
            b.set_max_proto_version(Some(version)).unwrap();
            let none = b.build();
            assert_eq!(
                failure_reason(&pki, move |s| {
                    // TLS 1.3 reports the refusal after the client's Finished.
                    if let Ok(mut s) = none.connect("localhost", s) {
                        let _ = s.read(&mut [0; 1]);
                    }
                }),
                "no_client_certificate",
                "{version:?}"
            );
        }
        let foreign = connector(&pki, Some(&pki.foreign), true);
        assert_eq!(
            failure_reason(&pki, move |s| {
                if let Ok(mut s) = foreign.connect("localhost", s) {
                    let _ = s.read(&mut [0; 1]);
                }
            }),
            "certificate_rejected"
        );
        // The client does not trust the server certificate and aborts with an alert.
        let distrustful = connector(&pki, Some(&pki.client), false);
        assert_eq!(
            failure_reason(&pki, move |s| {
                let _ = distrustful.connect("localhost", s);
            }),
            "peer_alert"
        );
        let mut old = SslConnector::builder(SslMethod::tls_client()).unwrap();
        old.set_min_proto_version(Some(SslVersion::TLS1_1)).unwrap();
        old.set_max_proto_version(Some(SslVersion::TLS1_1)).unwrap();
        old.set_cipher_list("DEFAULT:@SECLEVEL=0").unwrap();
        let old = old.build();
        assert_eq!(
            failure_reason(&pki, move |s| {
                let _ = old.connect("localhost", s);
            }),
            "protocol_version"
        );
        assert_eq!(
            failure_reason(&pki, |mut s| {
                let _ = s.write_all(b"GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n");
                let _ = s.read(&mut [0; 1]);
            }),
            "not_tls"
        );
        assert_eq!(failure_reason(&pki, drop), "connection_closed");
    }

    fn ec_key(curve: Nid) -> PKey<Private> {
        PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(curve).unwrap()).unwrap())
            .unwrap()
    }
    /// A PKI whose CA, server and client use ECDSA keys on one curve.
    fn ec_pki(curve: Nid, digest: MessageDigest) -> Pki {
        let dir = tempfile::tempdir().unwrap();
        let ca = issue_key(ec_key(curve), "suite b ca", None, "ca", digest);
        let server = issue_key(ec_key(curve), "localhost", Some(&ca), "server", digest);
        let client = issue_key(ec_key(curve), "client", Some(&ca), "client", digest);
        let foreign = issue("foreign", None, "client");
        fs::write(dir.path().join("ca.pem"), ca.cert.to_pem().unwrap()).unwrap();
        fs::write(dir.path().join("server.pem"), server.cert.to_pem().unwrap()).unwrap();
        fs::write(
            dir.path().join("server.key"),
            server.key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        Pki {
            dir,
            client,
            foreign,
        }
    }
    /// A TLS 1.2 handshake from a client that offers exactly one suite, one
    /// key-exchange group and one signature scheme. Returns the server's
    /// negotiated suite and the curve of the client key it verified, and the
    /// curve of the server key the client verified.
    fn suite_b_handshake(
        pki: &Pki,
        suite: &str,
        group: &str,
        sigalg: &str,
    ) -> Result<(String, Nid, Nid), String> {
        let d = pki.dir.path();
        let acceptor = tls(
            &d.join("server.pem"),
            &d.join("server.key"),
            &d.join("ca.pem"),
            None,
            tls_profile::TlsProfile::Modern,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let curve = |cert: Option<X509>| {
            cert.and_then(|c| c.public_key().ok())
                .and_then(|k| k.ec_key().ok())
                .and_then(|k| k.group().curve_name())
                .unwrap_or(Nid::UNDEF)
        };
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut s = acceptor.accept(socket).map_err(|e| e.to_string())?;
            let _ = s.write_all(b"ok");
            let _ = s.flush();
            let mut b = [0; 1];
            let _ = s.read(&mut b);
            let cipher = s.ssl().current_cipher().unwrap();
            Ok::<_, String>((
                cipher.standard_name().unwrap_or(cipher.name()).to_owned(),
                curve(s.ssl().peer_certificate()),
            ))
        });
        let mut b = SslConnector::builder(SslMethod::tls_client()).unwrap();
        b.set_ca_file(d.join("ca.pem")).unwrap();
        b.set_certificate(&pki.client.cert).unwrap();
        b.set_private_key(&pki.client.key).unwrap();
        b.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
        b.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
        b.set_cipher_list(suite).unwrap();
        b.set_groups_list(group).unwrap();
        b.set_sigalgs_list(sigalg).unwrap();
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let client = connector_result(b.build(), socket);
        let server = server.join().unwrap()?;
        let server_curve = client?;
        Ok((server.0, server.1, server_curve))
    }
    fn connector_result(connector: SslConnector, socket: TcpStream) -> Result<Nid, String> {
        let mut s = connector
            .connect("localhost", socket)
            .map_err(|e| e.to_string())?;
        let mut b = [0; 2];
        s.read_exact(&mut b).map_err(|e| e.to_string())?;
        let _ = s.write_all(b"x");
        Ok(s.ssl()
            .peer_certificate()
            .and_then(|c| c.public_key().ok())
            .and_then(|k| k.ec_key().ok())
            .and_then(|k| k.group().curve_name())
            .unwrap_or(Nid::UNDEF))
    }

    // REQ:8cf0a440fc953e47 Suite B minLOS_128 test case transport: TLS 1.2 with TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 negotiates
    // REQ:68b8808c932462d2 Suite B minLOS_192 test case transport: TLS 1.2 with TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 negotiates
    // REQ:e615c251e480feda with a P-256 or P-384 ECDSA credential the server authenticates with ECDSA-256 or ECDSA-384
    // REQ:8e52108c89400eaa the server verifies a client's ECDSA-256 (and ECDSA-384) authentication
    // REQ:daad71a32ed6ea88 the server verifies a client's ECDSA-384 authentication
    // REQ:d8303666c398d613 1.3 Suite B minLOS_128 mandatory case, TLS part (messages: scripts/test_profile_mandatory_cases.py)
    // REQ:4e040d028568554e 1.3 Suite B minLOS_192 mandatory case, TLS part (messages: scripts/test_profile_mandatory_cases.py)
    // REQ:fcfccce47925cd55 1.4 Suite B minLOS_128 mandatory case, TLS part (messages: scripts/test_profile_mandatory_cases.py)
    // REQ:e89c9e824244a839 1.4 Suite B minLOS_192 mandatory case, TLS part (messages: scripts/test_profile_mandatory_cases.py)
    #[test]
    fn suite_b_credentials_negotiate_the_suite_b_cipher_suites() {
        for (curve, digest, suite, standard, group, sigalg) in [
            (
                Nid::X9_62_PRIME256V1,
                MessageDigest::sha256(),
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "P-256",
                "ECDSA+SHA256",
            ),
            (
                Nid::SECP384R1,
                MessageDigest::sha384(),
                "ECDHE-ECDSA-AES256-GCM-SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "P-384",
                "ECDSA+SHA384",
            ),
        ] {
            let pki = ec_pki(curve, digest);
            let (negotiated, client_curve, server_curve) =
                suite_b_handshake(&pki, suite, group, sigalg).unwrap();
            assert_eq!(negotiated, standard);
            assert_eq!(
                client_curve, curve,
                "server verified the client's ECDSA key"
            );
            assert_eq!(
                server_curve, curve,
                "client verified the server's ECDSA key"
            );
            // A client certificate from another CA is still refused.
            let foreign = Pki {
                dir: tempfile::tempdir().unwrap(),
                client: issue_key(ec_key(curve), "stranger", None, "client", digest),
                foreign: issue("unused", None, "client"),
            };
            for name in ["ca.pem", "server.pem", "server.key"] {
                fs::copy(pki.dir.path().join(name), foreign.dir.path().join(name)).unwrap();
            }
            assert!(suite_b_handshake(&foreign, suite, group, sigalg).is_err());
        }
        // Negative: an RSA server credential cannot negotiate the ECDSA suites.
        let rsa = pki();
        assert!(
            suite_b_handshake(
                &rsa,
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "P-256",
                "ECDSA+SHA256:RSA+SHA256:RSA-PSS+SHA256"
            )
            .is_err()
        );
    }

    // REQ:59fcaf549407e561 1.3-2.1: the TTLV listener uses the IANA port 5696 unless configured otherwise
    // REQ:e48b3b56e6afa01e 1.2 TLS 1.2 suite: port handling follows Basic 3.1.4 (default 5696)
    // REQ:2384d9f29cc394ae 1.3/1.4 TLS 1.2 suite: port handling follows Basic 3.1.4 (default 5696)
    // REQ:ff4ed6aa1fc6acca 1.3/1.4 Suite B: port handling follows 3.2.4 (default 5696)
    #[test]
    fn serve_listens_on_the_iana_kmip_port_by_default() {
        let args = Args::try_parse_from([
            "keytend-kmip-server",
            "serve",
            "--cert",
            "c",
            "--key",
            "k",
            "--ca",
            "a",
            "--policy",
            "p",
            "--master-key",
            "m",
        ])
        .unwrap();
        let Command::Serve(options) = args.command else {
            panic!("expected serve")
        };
        assert_eq!(options.listen.port(), 5696);
        assert_eq!(options.idle_timeout, 300);
        assert_eq!(options.destroyed_name_reuse, DestroyedNameReuse::Allow);
        assert_eq!(options.lease_states, LeaseStates::ActiveDeactivated);
        assert_eq!(
            options.get_attributes_none,
            GetAttributesNone::EmptyAttributes
        );
        assert_eq!(
            options.text_encoding.resolve(),
            keytend_kmip_server::encoding::TextEncoding::default()
        );
    }

    /// The default is `extended`; FIPS mode notes `--ec-curves extended`
    /// only when the operator chose it, not for the default.
    #[test]
    fn only_an_explicit_ec_curves_value_counts_as_chosen() {
        let chosen = |extra: &[&str]| {
            let base = [
                "keytend-kmip-server",
                "serve",
                "--cert",
                "c",
                "--key",
                "k",
                "--ca",
                "a",
                "--policy",
                "p",
                "--master-key",
                "m",
            ];
            // Without the KMIP_EC_CURVES binding, so a value in the test
            // environment cannot stand in for the default.
            let matches = <Args as clap::CommandFactory>::command()
                .mut_subcommand("serve", |s| s.mut_arg("ec_curves", |a| a.env(None)))
                .try_get_matches_from(base.iter().chain(extra))
                .unwrap();
            let args = <Args as clap::FromArgMatches>::from_arg_matches(&matches).unwrap();
            let Command::Serve(options) = args.command else {
                panic!("expected serve")
            };
            (ec_curves_chosen(&matches), options.ec_curves)
        };
        assert_eq!(chosen(&[]), (false, EcCurves::Extended));
        assert_eq!(
            chosen(&["--ec-curves", "extended"]),
            (true, EcCurves::Extended)
        );
        assert_eq!(chosen(&["--ec-curves", "nist"]), (true, EcCurves::Nist));
        let other = <Args as clap::CommandFactory>::command()
            .try_get_matches_from(["keytend-kmip-server", "tls-profiles"])
            .unwrap();
        assert!(!ec_curves_chosen(&other));
    }

    fn serve_options(extra: &[&str]) -> Result<Box<ServeOptions>, clap::Error> {
        let base = [
            "keytend-kmip-server",
            "serve",
            "--cert",
            "c",
            "--key",
            "k",
            "--ca",
            "a",
            "--policy",
            "p",
            "--master-key",
            "m",
        ];
        let args = Args::try_parse_from(base.iter().chain(extra))?;
        let Command::Serve(options) = args.command else {
            panic!("expected serve")
        };
        Ok(options)
    }
    #[test]
    fn idle_timeout_name_reuse_and_text_forms_are_validated_at_startup() {
        assert_eq!(idle_limit(300), Some(Duration::from_secs(300)));
        assert_eq!(idle_limit(0), None);
        let options = serve_options(&["--idle-timeout", "0"]).unwrap();
        assert_eq!(idle_limit(options.idle_timeout), None);
        assert_eq!(
            serve_options(&["--idle-timeout", "604800"])
                .unwrap()
                .idle_timeout,
            MAX_IDLE_TIMEOUT
        );
        let options = serve_options(&[
            "--destroyed-name-reuse",
            "reserve",
            "--text-encoding",
            "readable",
            "--xml-tags",
            "hex",
            "--lease-states",
            "active",
            "--get-attributes-none",
            "identifier-only",
            "--ec-curves",
            "extended",
        ])
        .unwrap();
        assert_eq!(
            options.get_attributes_none,
            GetAttributesNone::IdentifierOnly
        );
        assert_eq!(options.ec_curves, EcCurves::Extended);
        assert_eq!(
            serve_options(&["--ec-curves", "nist"]).unwrap().ec_curves,
            EcCurves::Nist
        );
        assert!(serve_options(&["--ec-curves", "brainpool"]).is_err());
        assert!(serve_options(&["--ec-curves", "all"]).is_err());
        assert_eq!(options.destroyed_name_reuse, DestroyedNameReuse::Reserve);
        assert_eq!(options.lease_states, LeaseStates::Active);
        let forms = options.text_encoding.resolve();
        assert_eq!(forms.xml_tags, keytend_kmip_server::encoding::NameForm::Hex);
        assert_eq!(
            forms.json_enumerations,
            keytend_kmip_server::encoding::EnumerationForm::Name
        );
        for bad in [
            &["--idle-timeout", "-1"][..],
            &["--idle-timeout", "604801"],
            &["--idle-timeout", "5m"],
            &["--destroyed-name-reuse", "never"],
            &["--lease-states", "deactivated"],
            &["--get-attributes-none", "identifier"],
            &["--get-attributes-none", "empty"],
            &["--text-encoding", "names"],
            &["--json-masks", "pipe"],
        ] {
            assert!(serve_options(bad).is_err(), "{bad:?}");
        }
    }

    /// A CA with keyCertSign, as a provisioning CA must have.
    fn signing_ca(name: &str, key: PKey<Private>, digest: MessageDigest) -> Identity {
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(rand_serial()).unwrap();
        b.set_serial_number(&Asn1Integer::from_bn(&serial).unwrap())
            .unwrap();
        b.set_subject_name(&subject).unwrap();
        b.set_issuer_name(&subject).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
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
        b.sign(&key, digest).unwrap();
        Identity {
            cert: b.build(),
            key,
        }
    }

    #[test]
    fn provisioning_ca_checks_and_self_test_run_at_startup() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let p384 = || {
            PKey::from_ec_key(
                EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap(),
            )
            .unwrap()
        };
        let rsa_ca = signing_ca(
            "provisioning",
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            MessageDigest::sha256(),
        );
        let ec_ca = signing_ca("suite b provisioning", p384(), MessageDigest::sha384());
        let other = signing_ca(
            "elsewhere",
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            MessageDigest::sha256(),
        );
        let server = issue("localhost", Some(&rsa_ca), "server");
        fs::write(d.join("server.pem"), server.cert.to_pem().unwrap()).unwrap();
        let mut bundle = rsa_ca.cert.to_pem().unwrap();
        bundle.extend(ec_ca.cert.to_pem().unwrap());
        fs::write(d.join("ca.pem"), &bundle).unwrap();
        let write = |name: &str, id: &Identity, mode: u32| {
            fs::write(d.join(format!("{name}.pem")), id.cert.to_pem().unwrap()).unwrap();
            let key = d.join(format!("{name}.key"));
            fs::write(&key, id.key.private_key_to_pem_pkcs8().unwrap()).unwrap();
            fs::set_permissions(&key, fs::Permissions::from_mode(mode)).unwrap();
        };
        write("rsa", &rsa_ca, 0o600);
        write("ec", &ec_ca, 0o640);
        write("other", &other, 0o600);
        let policy_path = d.join("policy.json");
        fs::write(
            &policy_path,
            serde_json::json!({"principals": {"a".repeat(64): {"name": "db", "operations": [53]}}})
                .to_string(),
        )
        .unwrap();
        let policy = read_policy(&policy_path).unwrap();
        let load = |name: &str, profile| {
            provisioning(
                &d.join(format!("{name}.pem")),
                &d.join(format!("{name}.key")),
                &d.join("server.pem"),
                &d.join("ca.pem"),
                None,
                profile,
                false,
                &policy,
            )
            .map(drop)
            .map_err(|e| format!("{e:#}"))
        };
        use tls_profile::TlsProfile;
        load("rsa", TlsProfile::Modern).unwrap();
        load("ec", TlsProfile::Kmip1SuiteB192).unwrap();
        load("ec", TlsProfile::Kmip1SuiteB128).unwrap();
        // A Suite B profile refuses what an RSA CA issues.
        let error = load("rsa", TlsProfile::Kmip1SuiteB192).unwrap_err();
        assert!(error.contains("listener's verification"), "{error}");
        // The CA must be in the --ca bundle.
        let error = load("other", TlsProfile::Modern).unwrap_err();
        assert!(error.contains("--ca bundle"), "{error}");
        // The key file must not be accessible to other users.
        fs::set_permissions(d.join("rsa.key"), fs::Permissions::from_mode(0o604)).unwrap();
        let error = load("rsa", TlsProfile::Modern).unwrap_err();
        assert!(error.contains("other users"), "{error}");
        // A certificate that is not a CA.
        write("server", &server, 0o600);
        let error = load("server", TlsProfile::Modern).unwrap_err();
        assert!(error.contains("not a CA"), "{error}");
        // Both flags or neither.
        assert!(serve_options(&["--provisioning-ca", "x"]).is_err());
        assert!(serve_options(&["--provisioning-ca-key", "x"]).is_err());
        let options =
            serve_options(&["--provisioning-ca", "x", "--provisioning-ca-key", "y"]).unwrap();
        assert_eq!(options.provisioning_ca, Some(PathBuf::from("x")));
    }

    #[test]
    fn the_listener_verifier_follows_the_handshake_rules() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let root = issue("root", None, "ca");
        let intermediate = issue("intermediate", Some(&root), "ca");
        let client = issue("client", Some(&intermediate), "client");
        let server = issue("server", Some(&root), "server");
        let weak = issue_key(
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            "weak",
            Some(&root),
            "client",
            MessageDigest::sha1(),
        );
        fs::write(d.join("ca.pem"), root.cert.to_pem().unwrap()).unwrap();
        let verify =
            listener_verifier(&d.join("ca.pem"), None, tls_profile::TlsProfile::Modern).unwrap();
        // The client-sent intermediate completes the chain.
        assert!(verify(&client.cert, &[]).is_err());
        verify(&client.cert, std::slice::from_ref(&intermediate.cert)).unwrap();
        // Purpose sslclient: a serverAuth-only certificate is refused, and so
        // is a SHA-1 signature.
        assert!(verify(&server.cert, &[]).is_err());
        let error = verify(&weak.cert, &[]).unwrap_err();
        assert!(error.contains("weak digest"), "{error}");
        // Suite B: an RSA chain is refused.
        let suite_b = listener_verifier(
            &d.join("ca.pem"),
            None,
            tls_profile::TlsProfile::Kmip1SuiteB128,
        )
        .unwrap();
        assert!(suite_b(&client.cert, std::slice::from_ref(&intermediate.cert)).is_err());
    }

    #[test]
    fn resolve_principal_lets_the_store_override_the_policy() {
        let (old, new, other) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        let policy = |entries: serde_json::Value| {
            fs::write(
                &path,
                serde_json::json!({ "principals": entries }).to_string(),
            )
            .unwrap();
            read_policy(&path).unwrap()
        };
        let resolved = |policy: &Policy, lookup: &Lookup, fp: &str| {
            resolve_principal(policy, lookup, fp).map(|(entry, key)| (entry.name, key))
        };
        let replacement = |principal: &str| Lookup::Replacement {
            policy_fingerprint: old.clone(),
            principal: principal.to_owned(),
        };
        let anchor = policy(serde_json::json!({
            &old: {"name": "db", "operations": [1]},
            &other: {"name": "other", "operations": [1]},
        }));
        // No record: the policy alone decides.
        assert_eq!(
            resolved(&anchor, &Lookup::Unknown, &old),
            Some(("db".into(), old.clone()))
        );
        assert_eq!(resolved(&anchor, &Lookup::Unknown, &new), None);
        // Retired: refused although the policy lists it.
        assert_eq!(resolved(&anchor, &Lookup::Retired, &old), None);
        // Replacement through its anchor (the replaced certificate's entry).
        assert_eq!(
            resolved(&anchor, &replacement("db"), &new),
            Some(("db".into(), old.clone()))
        );
        // The anchor's name must be the recorded principal.
        assert_eq!(resolved(&anchor, &replacement("other"), &new), None);
        // A direct entry under the same name (folded in): the anchor still
        // decides while it exists, the direct entry once it is gone.
        let folded = policy(serde_json::json!({
            &old: {"name": "db", "operations": [1]},
            &new: {"name": "db", "operations": [1, 2]},
        }));
        assert_eq!(
            resolved(&folded, &replacement("db"), &new),
            Some(("db".into(), old.clone()))
        );
        let folded_only = policy(serde_json::json!({&new: {"name": "db", "operations": [1]}}));
        assert_eq!(
            resolved(&folded_only, &replacement("db"), &new),
            Some(("db".into(), new.clone()))
        );
        // A direct entry under another name never remaps a replacement,
        // with or without the anchor.
        let crossed = policy(serde_json::json!({
            &old: {"name": "db", "operations": [1]},
            &new: {"name": "other", "operations": [1]},
        }));
        assert_eq!(resolved(&crossed, &replacement("db"), &new), None);
        let crossed_only = policy(serde_json::json!({&new: {"name": "other", "operations": [1]}}));
        assert_eq!(resolved(&crossed_only, &replacement("db"), &new), None);
        // Neither anchor nor direct entry: refused.
        let neither = policy(serde_json::json!({&other: {"name": "other", "operations": [1]}}));
        assert_eq!(resolved(&neither, &replacement("db"), &new), None);
    }

    #[test]
    fn client_identity_and_reverse_only_endpoints_are_validated() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        let read = |policy: serde_json::Value| {
            fs::write(&path, policy.to_string()).unwrap();
            read_policy(&path)
        };
        let policy = read(serde_json::json!({"principals": {
            &a: {"name": "database", "operations": [1], "client_identity": "credential"},
            &b: {"name": "other", "operations": [1]},
        }}))
        .unwrap();
        assert!(policy.principals[&a].client_identity == ClientIdentity::Credential);
        assert!(policy.principals[&b].client_identity == ClientIdentity::Certificate);
        // Certificates of one principal must agree; unknown values fail.
        for identity in [serde_json::json!("certificate"), serde_json::json!("user")] {
            assert!(
                read(serde_json::json!({"principals": {
                    &a: {"name": "database", "operations": [1], "client_identity": "credential"},
                    &b: {"name": "database", "operations": [1], "client_identity": identity},
                }}))
                .is_err()
            );
        }
        let endpoint = |operations: serde_json::Value, version: &str| {
            serde_json::json!({"principals": {&a: {
                "name": "database", "operations": operations,
                "client_endpoint": {"protocol_version": version, "operations": [28]},
            }}})
        };
        assert!(read(endpoint(serde_json::json!([10, 50]), "2.1")).is_ok());
        // Without an address only Set Endpoint Role (2.0+) can carry messages.
        assert!(read(endpoint(serde_json::json!([10]), "2.1")).is_err());
        assert!(read(endpoint(serde_json::json!([10, 50]), "1.4")).is_err());
        let mut partial = endpoint(serde_json::json!([10, 50]), "2.1");
        partial["principals"][&a]["client_endpoint"]["address"] = "127.0.0.1:5697".into();
        assert!(read(partial).is_err());
    }
    #[test]
    fn https_client_endpoints_need_dial_out_and_an_origin_form_target() {
        let a = "a".repeat(64);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        let read = |extra: serde_json::Value, dial: bool| {
            let mut endpoint = serde_json::json!({"protocol_version": "1.4", "operations": [28]});
            if dial {
                for (k, v) in [
                    ("address", "agent.example:5697"),
                    ("server_name", "agent.example"),
                    ("ca", "/ca.pem"),
                    ("certificate", "/c.pem"),
                    ("key", "/c.key"),
                ] {
                    endpoint[k] = v.into();
                }
            }
            for (k, v) in extra.as_object().unwrap() {
                endpoint[k] = v.clone();
            }
            fs::write(
                &path,
                serde_json::json!({"principals": {&a: {
                    "name": "database", "operations": [10, 50], "client_endpoint": endpoint,
                }}})
                .to_string(),
            )
            .unwrap();
            read_policy(&path)
        };
        let transport = |p: Policy| {
            p.principals
                .values()
                .next()
                .unwrap()
                .client_endpoint
                .clone()
                .unwrap()
                .transport()
        };
        assert_eq!(
            transport(read(serde_json::json!({}), true).unwrap()),
            keytend_kmip_server::delivery::Transport::Ttlv
        );
        assert_eq!(
            transport(read(serde_json::json!({"transport": "https"}), true).unwrap()),
            keytend_kmip_server::delivery::Transport::Https {
                target: "/kmip".into()
            }
        );
        assert_eq!(
            transport(
                read(
                    serde_json::json!({"transport": "https", "target": "/kms/v1"}),
                    true
                )
                .unwrap()
            ),
            keytend_kmip_server::delivery::Transport::Https {
                target: "/kms/v1".into()
            }
        );
        for (extra, dial) in [
            // HTTPS needs a dial-out address: reversed channels are TTLV.
            (serde_json::json!({"transport": "https"}), false),
            (serde_json::json!({"target": "/kmip"}), true),
            (
                serde_json::json!({"transport": "https", "target": "kmip"}),
                true,
            ),
            (
                serde_json::json!({"transport": "https", "target": "/a b"}),
                true,
            ),
            (serde_json::json!({"transport": "http"}), true),
        ] {
            assert!(read(extra.clone(), dial).is_err(), "{extra}");
        }
    }
    #[test]
    fn users_bind_to_policy_fingerprints_and_agree_per_principal() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.json");
        fs::write(
            &policy_path,
            serde_json::json!({"principals": {
                &a: {"name": "database", "operations": [1]},
                &b: {"name": "database", "operations": [1]},
            }})
            .to_string(),
        )
        .unwrap();
        let policy = read_policy(&policy_path).unwrap();
        let user = |name: &str| {
            serde_json::to_value(
                keytend_kmip_server::credentials::PasswordVerifier::new(b"pw").unwrap(),
            )
            .map(|v| serde_json::json!({"username": name, "password_scrypt": v}))
            .unwrap()
        };
        let read = |users: serde_json::Value| {
            let path = dir.path().join("users.json");
            fs::write(&path, users.to_string()).unwrap();
            read_users(&path, &policy, false)
        };
        let admin = user("administrator");
        let users =
            read(serde_json::json!({"users": {&a: [admin.clone()], &b: [admin.clone()]}})).unwrap();
        assert_eq!(users.users["database"].len(), 1);
        assert!(users.devices.is_empty());
        let device = serde_json::json!({
            "name": "meter",
            "device_serial_number": "serNum123456",
            "password_scrypt": admin["password_scrypt"].clone(),
        });
        let both =
            read(serde_json::json!({"users": {}, "devices": {&a: [device.clone()]}})).unwrap();
        assert_eq!(both.devices["database"].len(), 1);
        assert!(
            read(serde_json::json!({"users": {}, "devices": {&a: [device.clone()], &b: []}}))
                .is_err()
        );
        let mut anonymous = device.clone();
        anonymous
            .as_object_mut()
            .unwrap()
            .remove("device_serial_number");
        assert!(read(serde_json::json!({"users": {}, "devices": {&a: [anonymous]}})).is_err());
        assert!(read(serde_json::json!({"users": {"c".repeat(64): [admin.clone()]}})).is_err());
        assert!(
            read(serde_json::json!({"users": {&a: [admin.clone()], &b: [user("other")]}})).is_err()
        );
        assert!(read(serde_json::json!({"users": {&a: [admin.clone()]}, "extra": 1})).is_err());
        let mut plaintext = admin.clone();
        plaintext["password"] = "pw".into();
        assert!(read(serde_json::json!({"users": {&a: [plaintext]}})).is_err());
    }
    #[test]
    fn stored_credential_secrets_require_the_explicit_opt_in() {
        let a = "a".repeat(64);
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.json");
        fs::write(
            &policy_path,
            serde_json::json!({"principals": {&a: {"name": "database", "operations": [1]}}})
                .to_string(),
        )
        .unwrap();
        let policy = read_policy(&policy_path).unwrap();
        let verifier = serde_json::to_value(
            keytend_kmip_server::credentials::PasswordVerifier::new(b"pw").unwrap(),
        )
        .unwrap();
        let read = |user: serde_json::Value, allow: bool| {
            let path = dir.path().join("users.json");
            fs::write(
                &path,
                serde_json::json!({"users": {&a: [user]}}).to_string(),
            )
            .unwrap();
            read_users(&path, &policy, allow)
        };
        let base = serde_json::json!({"username": "Fred", "password_scrypt": verifier});
        let s1 = hex::encode(openssl::sha::sha256(b"Fredpw"));
        let mut hashed = base.clone();
        hashed["hashed_password"] = serde_json::json!({"s1": s1, "s2_scrypt": verifier});
        let mut otp = base.clone();
        otp["one_time_password"] = serde_json::json!({"seed": "00".repeat(20)});
        for user in [&hashed, &otp] {
            assert!(read(user.clone(), false).is_err());
            let read = read(user.clone(), true).unwrap();
            assert!(read.users["database"][0].stores_secrets());
        }
        assert!(!read(base.clone(), false).unwrap().users["database"][0].stores_secrets());
        // Malformed material is refused even with the opt-in.
        let mut bad = hashed.clone();
        bad["hashed_password"]["hashing_algorithm"] = "SHA-1".into();
        assert!(read(bad, true).is_err());
        let mut bad = hashed.clone();
        bad["hashed_password"]["hashing_algorithm"] = "SHA-512".into();
        assert!(read(bad, true).is_err());
        let mut bad = otp.clone();
        bad["one_time_password"]["seed"] = "00".repeat(8).into();
        assert!(read(bad, true).is_err());
        let mut bad = otp.clone();
        bad["one_time_password"]["algorithm"] = "HOTP".into();
        assert!(read(bad, true).is_err());
    }
}
