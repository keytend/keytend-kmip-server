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

//! Maintenance steps that run as single commands, so an image without a
//! shell can run them (Kubernetes init containers, Jobs and CronJobs):
//! directory backups with retention, restore, and in-place master-key
//! rotation and its revert. Every step that replaces the database runs under
//! the writer lock and leaves the files in a state that a second run either
//! completes or refuses with a recovery message.
//!
//! The database `D` (for example `/data/kmip.sqlite`) lives in directory
//! `dir`. The files are:
//!
//! - `D`, `D-wal`, `D-shm`, `D-journal`: the database "family", always
//!   moved together, the main file first.
//! - `D.lock`: the writer lock (`store::WriterLock`).
//! - `D.last-backup`: Unix time of the last successful `backup`.
//! - `dir/.restore-<id>`: restore `<id>` completed; `dir/pre-restore-<id>/`:
//!   the database it replaced; `dir/.restore-<id>.sqlite.tmp`: its staged copy.
//! - `D.rotated`: a verified rotated copy; `D.rotation.json`: the cutover of a
//!   rotation into `dir/pre-rotation-<UTC time>/` has begun.
//! - `D.revert.json`: a revert to `pre-rotation-<time>` (the rotated
//!   database going to `dir/post-rotation-<time>/`) has begun.
//!
//! Records (`.rotation.json`, `.revert.json`, `.restore-<id>`) are published
//! atomically: written and synced under a temporary name, linked into place
//! without replacing anything, then the directory is synced. `serve` refuses
//! to start while a record says a cutover is unfinished, so it never creates
//! an empty database where the real one has been moved aside.
//!
//! Every recovery path verifies what it is about to install, including the
//! audit checkpoint it was given, before it moves another file; when a
//! check fails after an earlier run already changed the live files, the
//! error says so.
use crate::store::{
    RotationSummary, STORAGE_SCHEMA, Store, Verification, WriterLock, now,
    require_rollback_journal, sidecar,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

/// SQLite files of one database, the main file first.
const FAMILY: [&str; 4] = ["", "-wal", "-shm", "-journal"];
/// Prefix of the temporary files records are staged in.
const STAGING: &str = ".keytend-kmip-server-journal-";

/// Test crash points: a debug build exits with status 86 at the step named
/// by `KEYTEND_KMIP_SERVER_TEST_FAULT`, without cleaning up, as a killed
/// process would. Release builds have no crash points.
fn fault(point: &str) {
    #[cfg(debug_assertions)]
    if std::env::var_os("KEYTEND_KMIP_SERVER_TEST_FAULT").is_some_and(|v| v == point) {
        std::process::exit(86);
    }
    #[cfg(not(debug_assertions))]
    let _ = point;
}

/// Test pause points: a debug build creates the file named by
/// `KEYTEND_KMIP_SERVER_TEST_PAUSE_FILE` at the step named by
/// `KEYTEND_KMIP_SERVER_TEST_PAUSE` and waits (up to a minute) until the test
/// removes it. Release builds have none.
fn pause(point: &str) {
    #[cfg(debug_assertions)]
    if std::env::var_os("KEYTEND_KMIP_SERVER_TEST_PAUSE").is_some_and(|v| v == point)
        && let Some(file) = std::env::var_os("KEYTEND_KMIP_SERVER_TEST_PAUSE_FILE")
    {
        let file = PathBuf::from(file);
        let _ = fs::write(&file, b"paused");
        for _ in 0..6000 {
            if !file.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = point;
}

/// How long a cutover waits for reads of the database to finish.
const CUTOVER_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Held by `check-store`, `backup` and `audit-checkpoint` while they read a
/// database: a shared `flock` on the database's directory. Commands that
/// move database files (`restore`, `rotate-master-key --in-place`) take it
/// exclusively, so a reader never creates `-wal`/`-shm` files in the middle
/// of a cutover. A directory can be locked on a read-only mount, and the
/// server, which reads and writes through SQLite's own locking, takes no
/// part. Dropping the guard releases it.
pub struct ReadGuard {
    directories: Vec<fs::File>,
}

impl Drop for ReadGuard {
    fn drop(&mut self) {
        for directory in &self.directories {
            let _ = rustix::fs::flock(directory, rustix::fs::FlockOperation::Unlock);
        }
    }
}

/// A shared lock on `dir`, failing at once while a cutover holds it.
fn shared_directory_lock(dir: &Path) -> Result<fs::File> {
    let directory =
        fs::File::open(dir).with_context(|| format!("open directory {}", dir.display()))?;
    match rustix::fs::flock(
        &directory,
        rustix::fs::FlockOperation::NonBlockingLockShared,
    ) {
        Ok(()) => Ok(directory),
        Err(rustix::io::Errno::WOULDBLOCK) => bail!(
            "a restore or master-key rotation is changing the database files in {}: retry when it has finished",
            dir.display()
        ),
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}

/// Whether the unfinished cutover of `live` (a database whose records are in
/// its directory) still has files moving through the archive directory
/// `archive` (a name in the same directory). Unreadable records count.
fn archive_in_use(live: &Layout, archive: &str) -> Result<bool> {
    match read_record::<RotationJournal>(&live.rotation_journal())? {
        Record::Valid(journal) if journal.pre == archive => return Ok(true),
        Record::Torn => return Ok(true),
        _ => {}
    }
    match read_record::<RevertJournal>(&live.revert_journal())? {
        Record::Valid(journal) if journal.pre == archive || journal.post == archive => {
            return Ok(true);
        }
        Record::Torn => return Ok(true),
        _ => {}
    }
    match read_record::<RestoreIntent>(&live.restore_intent())? {
        Record::Valid(intent) if format!("pre-restore-{}", intent.id) == archive => Ok(true),
        Record::Torn => Ok(true),
        _ => Ok(false),
    }
}

/// Start reading `database`: refuse while a cutover runs or is unfinished.
/// That includes a database in an archive directory (`pre-rotation-*`,
/// `post-rotation-*`, `pre-restore-*`) whose owning cutover, recorded next
/// to the live database one level up, is unfinished: a reader would create
/// `-wal`/`-shm` files there that block the moves still to come.
pub fn read_guard(database: &Path) -> Result<ReadGuard> {
    // Absolute, so a relative path to a file in an archive directory still
    // finds the live database one level up.
    let database = &std::path::absolute(database)
        .with_context(|| format!("resolve {}", database.display()))?;
    let layout = Layout::new(database)?;
    let mut directories = vec![shared_directory_lock(&layout.dir)?];
    if let Some(unfinished) = unfinished_maintenance(database, false)? {
        bail!("{unfinished}; the database is not read until then");
    }
    let archive = layout
        .dir
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| {
            stamped(n, "pre-rotation-")
                || stamped(n, "post-rotation-")
                || n.strip_prefix("pre-restore-").is_some_and(valid_restore_id)
        })
        .map(str::to_string);
    if let Some(archive) = archive
        && let Some(parent) = layout.dir.parent().filter(|p| p.is_dir())
    {
        let live = Layout::new(&parent.join(&layout.name))?;
        directories.push(shared_directory_lock(&live.dir)?);
        if archive_in_use(&live, &archive)? {
            let unfinished = unfinished_maintenance(&live.database, false)?.unwrap_or_else(|| {
                format!("a cutover of {} is unfinished", live.database.display())
            });
            bail!(
                "{} is in {archive}, which an unfinished cutover still uses: {unfinished}; it is not read until then",
                database.display()
            );
        }
    }
    Ok(ReadGuard { directories })
}

/// The exclusive side of `ReadGuard`, for commands that move database files.
/// Waits up to `CUTOVER_WAIT` for reads in progress.
struct CutoverLock {
    _directory: fs::File,
}

impl Drop for CutoverLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self._directory, rustix::fs::FlockOperation::Unlock);
    }
}

impl CutoverLock {
    fn acquire(layout: &Layout) -> Result<Self> {
        let directory = fs::File::open(&layout.dir)
            .with_context(|| format!("open directory {}", layout.dir.display()))?;
        let deadline = std::time::Instant::now() + CUTOVER_WAIT;
        loop {
            match rustix::fs::flock(
                &directory,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            ) {
                Ok(()) => {
                    return Ok(Self {
                        _directory: directory,
                    });
                }
                Err(rustix::io::Errno::WOULDBLOCK) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(rustix::io::Errno::WOULDBLOCK) => bail!(
                    "a check-store, backup or audit-checkpoint of a database in {} is still reading after {} seconds; nothing changed, retry when it has finished",
                    layout.dir.display(),
                    CUTOVER_WAIT.as_secs()
                ),
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
    }
}

/// What a maintenance command did, as lines for standard output.
#[derive(Debug)]
pub struct Outcome {
    /// False when the command found its work already done.
    pub changed: bool,
    pub messages: Vec<String>,
}

/// `(year, month, day, hour, minute, second)` of a Unix time in UTC.
fn civil(seconds: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400) as u32;
    // Howard Hinnant's days-to-civil algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day, rest / 3600, rest / 60 % 60, rest % 60)
}

/// `20261105T021500Z`.
pub fn compact_utc(seconds: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(seconds);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// `2026-11-05T02:15:00Z`.
pub fn rfc3339_utc(seconds: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(seconds);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// `prefix` followed by a `compact_utc` time and, for the archives of an
/// in-place rotation, `-<n>` (unique among this database's pre- and
/// post-rotation names; the Docker script's names have none). Returns the
/// time and `n` (0 without one), which order the names.
fn archive_key(name: &str, prefix: &str) -> Option<(String, u32)> {
    let rest = name.strip_prefix(prefix)?;
    let (stamp, counter) = match rest.split_once('-') {
        Some((stamp, counter)) => (stamp, Some(counter)),
        None => (rest, None),
    };
    let b = stamp.as_bytes();
    let valid = b.len() == 16
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'T'
        && b[9..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'Z';
    let n = match counter {
        None => 0,
        Some(c) if !c.is_empty() && c.len() <= 9 && c.bytes().all(|b| b.is_ascii_digit()) => {
            c.parse().ok()?
        }
        Some(_) => return None,
    };
    valid.then(|| (stamp.to_string(), n))
}

fn stamped(name: &str, prefix: &str) -> bool {
    archive_key(name, prefix).is_some()
}

/// Size and SHA-256 of a file: the durable identity of a backup or of a
/// restore's copy. Device and inode change across remounts; the content of
/// a file nothing writes does not.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub bytes: u64,
    pub sha256: String,
}

/// The witness of `path`, read in 64 KiB chunks.
pub fn witness(path: &Path) -> Result<Witness> {
    use std::io::Read;
    let mut file = fs::File::open(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())?;
    let mut buffer = vec![0; 64 * 1024];
    let mut bytes = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n])?;
        bytes += n as u64;
    }
    Ok(Witness {
        bytes,
        sha256: hex::encode(hasher.finish()?),
    })
}

/// The mount points listed in `/proc/self/mountinfo` (empty where there is
/// no such file).
fn mount_points() -> Result<std::collections::HashSet<PathBuf>> {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return Ok(Default::default());
    };
    let unescape = |field: &str| -> PathBuf {
        let bytes = field.as_bytes();
        let mut out = vec![];
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\'
                && i + 3 < bytes.len()
                && bytes[i + 1..i + 4]
                    .iter()
                    .all(|b| (b'0'..=b'7').contains(b))
            {
                let value =
                    (bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + (bytes[i + 3] - b'0');
                out.push(value);
                i += 4;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(std::ffi::OsString::from_vec(out))
    };
    Ok(text
        .lines()
        .filter_map(|line| line.split(' ').nth(4).map(unescape))
        .collect())
}

/// Refuse a database whose files are mount points of their own (a file
/// bind mount): they cannot be moved, so a cutover could not begin. A
/// mounted directory that holds the database is fine.
fn refuse_file_mounts(layout: &Layout) -> Result<()> {
    let mounts = mount_points()?;
    let dir = fs::canonicalize(&layout.dir)?;
    for suffix in FAMILY {
        let path = layout.member(&dir, suffix);
        if mounts.contains(&path) {
            bail!(
                "{} is a mount point of its own (a file mount): restore and in-place rotation move the database's files, which a file mount does not allow. Mount the directory that holds the database instead (for example /data); nothing was moved",
                path.display()
            );
        }
    }
    Ok(())
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(anyhow::Error::new(e).context(format!("inspect {}", path.display()))),
    }
}

fn sync_dir(dir: &Path) -> Result<()> {
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("sync directory {}", dir.display()))
}

fn private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))
}

/// Write `bytes` to `path` atomically (temporary file, fsync, rename, fsync
/// of the directory), mode 0600, replacing any earlier file.
fn write_replacing(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)
        .map_err(|e| anyhow::Error::new(e.error).context(format!("write {}", path.display())))?;
    sync_dir(dir)
}

/// Publish a new record: write and sync it under a temporary name (mode
/// 0600), link it into place without replacing anything, then sync the
/// directory. A crash leaves either no record or the whole record.
fn publish_new(path: &Path, bytes: &[u8], point: &str) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::Builder::new().prefix(STAGING).tempfile_in(dir)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    fault(point);
    file.persist_noclobber(path)
        .map_err(|e| anyhow::Error::new(e.error).context(format!("publish {}", path.display())))?;
    sync_dir(dir)
}

/// Remove record staging files a killed run left in `dir`; none is ever
/// referenced. Call under the writer lock.
fn remove_stale_staging(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(STAGING) && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// The database path split into its directory and file name.
#[derive(Clone)]
struct Layout {
    database: PathBuf,
    dir: PathBuf,
    name: OsString,
}

impl Layout {
    fn new(database: &Path) -> Result<Self> {
        let name = database
            .file_name()
            .context("database path has no file name")?
            .to_os_string();
        let dir = database
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf();
        if !dir.is_dir() {
            bail!("database directory {} does not exist", dir.display());
        }
        Ok(Self {
            database: database.to_path_buf(),
            dir,
            name,
        })
    }
    /// The database's file `suffix` in `dir`.
    fn member(&self, dir: &Path, suffix: &str) -> PathBuf {
        let mut name = self.name.clone();
        name.push(suffix);
        dir.join(name)
    }
    fn rotated(&self) -> PathBuf {
        sidecar(&self.database, ".rotated")
    }
    fn rotation_journal(&self) -> PathBuf {
        sidecar(&self.database, ".rotation.json")
    }
    fn revert_journal(&self) -> PathBuf {
        sidecar(&self.database, ".revert.json")
    }
    /// The intent record of a restore whose cutover has begun.
    fn restore_intent(&self) -> PathBuf {
        sidecar(&self.database, ".restore.json")
    }
    /// Move the database family from `from` to `to` (main file first),
    /// refusing to replace anything. Returns how many files moved. `step`
    /// names the move for crash-point tests.
    fn move_family(&self, from: &Path, to: &Path, step: &str) -> Result<usize> {
        let mut moved = 0;
        for suffix in FAMILY {
            let source = self.member(from, suffix);
            if !exists(&source)? {
                continue;
            }
            let target = self.member(to, suffix);
            if exists(&target)? {
                bail!(
                    "cannot move {} to {}: the target already exists",
                    source.display(),
                    target.display()
                );
            }
            fs::rename(&source, &target)
                .with_context(|| format!("move {} to {}", source.display(), target.display()))?;
            if suffix.is_empty() {
                sync_dir(to)?;
                sync_dir(from)?;
                fault(&format!("{step}-moved-main"));
            }
            moved += 1;
        }
        sync_dir(to)?;
        sync_dir(from)?;
        Ok(moved)
    }
    /// Remove a file and its SQLite sidecars.
    fn remove_family_of(path: &Path) -> Result<()> {
        for suffix in FAMILY {
            let file = sidecar(path, suffix);
            if exists(&file)? {
                fs::remove_file(&file).with_context(|| format!("remove {}", file.display()))?;
            }
        }
        Ok(())
    }
}

/// Fail unless the two key files hold different keys.
fn distinct_keys(new: &Path, previous: &Path) -> Result<()> {
    let a = Store::read_master_key(new).context("read --master-key")?;
    let b = Store::read_master_key(previous).context("read --previous-master-key")?;
    if bool::from(a.ct_eq(&b)) {
        bail!("--master-key and --previous-master-key hold the same key");
    }
    Ok(())
}

/// Leave `output` as a checkpoint of `store`: write it (after verifying
/// `previous`, if given) or, if it exists, require that it verifies.
fn ensure_checkpoint(
    store: &Store,
    output: &Path,
    previous: Option<&Path>,
    messages: &mut Vec<String>,
) -> Result<()> {
    if exists(output)? {
        store.verify_audit_checkpoint(output).with_context(|| {
            format!(
                "checkpoint output {} already exists and does not verify against the store",
                output.display()
            )
        })?;
        messages.push(format!(
            "Audit checkpoint {} already verifies against the store",
            output.display()
        ));
    } else {
        store.write_audit_checkpoint(output, previous)?;
        messages.push(format!(
            "Audit checkpoint for the store's master key written to {}: start the server with it, and keep a copy in your checkpoint store",
            output.display()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------- backups

/// `<database>.last-backup`: Unix time of the last successful backup.
pub fn last_backup_path(database: &Path) -> PathBuf {
    sidecar(database, ".last-backup")
}

/// Record a successful backup of `database` at `time`. The caller ignores a
/// failure (a read-only data directory).
pub fn record_last_backup(database: &Path, time: i64) -> Result<()> {
    write_replacing(&last_backup_path(database), format!("{time}\n").as_bytes())
}

/// The recorded last-backup time, if any.
pub fn read_last_backup(database: &Path) -> Option<u64> {
    use std::io::Read;
    let mut text = String::new();
    fs::File::open(last_backup_path(database))
        .ok()?
        .take(64)
        .read_to_string(&mut text)
        .ok()?;
    text.trim().parse().ok()
}

/// One `backup --output-dir` run.
#[derive(Debug, Serialize)]
pub struct DirectoryBackup {
    pub file: String,
    #[serde(skip)]
    pub path: PathBuf,
    pub bytes: u64,
    pub created: String,
    pub created_unix: i64,
    pub verified: bool,
    pub verification: Verification,
    /// Older backups removed by `--retain`.
    pub pruned: Vec<String>,
    /// Older backups `--retain` would remove but kept, with the reason.
    pub kept: Vec<String>,
    /// Backup-named files in the directory that this command did not record
    /// (copied in, or written for another database); never removed.
    pub unrecorded: Vec<String>,
}

fn backup_name(name: &str) -> bool {
    name.strip_suffix(".sqlite")
        .is_some_and(|stem| stamped(stem, "backup-"))
}

/// The device and inode of a file.
fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

/// `DIR/backup-index.json`: the backups `backup --output-dir` wrote into
/// the directory, each with the database it copied. Retention removes only
/// files listed here for the same database, so backups of other databases,
/// files copied in by hand and look-alike names are never touched.
#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct BackupIndex {
    version: u32,
    backups: Vec<IndexedBackup>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct IndexedBackup {
    file: String,
    /// The canonical path of the database it copies.
    source: PathBuf,
    /// Size and SHA-256 of the file as written.
    bytes: u64,
    sha256: String,
    created_unix: i64,
}

const INDEX: &str = "backup-index.json";

fn read_index(dir: &Path) -> Result<BackupIndex> {
    let path = dir.join(INDEX);
    match fs::read(&path) {
        Ok(bytes) => {
            let version = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|value| value["version"].as_u64());
            if version == Some(1) {
                // Written by a development build that identified backups by
                // device and inode: its entries cannot be checked by content,
                // so they are no longer recorded (and never removed).
                return Ok(BackupIndex {
                    version: 2,
                    backups: vec![],
                });
            }
            let index: BackupIndex = serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "{} is damaged: repair or remove it (no backup was written or removed)",
                    path.display()
                )
            })?;
            if index.version != 2 {
                bail!("{} has unknown version {}", path.display(), index.version);
            }
            Ok(index)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BackupIndex {
            version: 2,
            backups: vec![],
        }),
        Err(e) => Err(anyhow::Error::new(e).context(format!("read {}", path.display()))),
    }
}

fn write_index(dir: &Path, index: &BackupIndex) -> Result<()> {
    let mut json = serde_json::to_vec_pretty(index)?;
    json.push(b'\n');
    write_replacing(&dir.join(INDEX), &json)
}

/// The file is still exactly the backup the index recorded: same size and
/// SHA-256 (so remounts, which change device numbers, do not matter), a
/// standalone rollback-journal SQLite file, and nothing has used it as a
/// database (no `-wal`, `-shm`, `-journal` or lock file).
fn unchanged(dir: &Path, entry: &IndexedBackup) -> Result<std::result::Result<(), &'static str>> {
    use std::io::Read;
    let path = dir.join(&entry.file);
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return Ok(Err("it no longer exists"));
    };
    if !metadata.is_file()
        || metadata.len() != entry.bytes
        || witness(&path)?.sha256 != entry.sha256
    {
        return Ok(Err("it is not the file the index recorded"));
    }
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o400 {
            return Ok(Err(
                "its mode is no longer 0400: it may be in use as a database",
            ));
        }
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        if exists(&sidecar(&path, suffix))? {
            return Ok(Err(
                "it has SQLite sidecar files: it was opened as a database",
            ));
        }
    }
    let mut header = [0u8; 20];
    if fs::File::open(&path)?.read_exact(&mut header).is_err()
        || &header[..16] != b"SQLite format 3\0"
        || header[18] != 1
        || header[19] != 1
    {
        return Ok(Err("it is not a standalone backup any more"));
    }
    Ok(Ok(()))
}

/// Remove one indexed backup. Backups are read-only (0400), so no writer
/// can use one as a database without changing its mode, which `unchanged`
/// rejects. Retention never creates, takes or removes a writer lock file: a
/// backup with one (a writer has started on it) is kept, and the check is
/// repeated immediately before the file is removed.
fn prune_one(dir: &Path, entry: &IndexedBackup) -> Result<std::result::Result<(), String>> {
    let path = dir.join(&entry.file);
    let lock_path = WriterLock::path_for(&path);
    let used = || -> Result<Option<String>> {
        Ok(exists(&lock_path)?
            .then(|| "it has a writer lock file: it was opened as a database".to_string()))
    };
    if let Some(reason) = used()? {
        return Ok(Err(reason));
    }
    if let Err(reason) = unchanged(dir, entry)? {
        return Ok(Err(reason.into()));
    }
    pause("retention-candidate-checked");
    if let Some(reason) = used()? {
        return Ok(Err(reason));
    }
    fs::remove_file(&path).with_context(|| format!("remove old backup {}", entry.file))?;
    Ok(Ok(()))
}

/// Write `dir/backup-<UTC time>.sqlite`, verify the published file, record
/// it in `dir/backup-index.json`, publish `dir/latest.json`, then keep the
/// newest `retain` backups of this database. Only indexed backups of the
/// same database are ever removed (`prune_one`), and runs into one directory
/// are serialised by `dir/.backup.lock`.
pub fn backup_to_directory(
    database: &Path,
    master_key: &Path,
    dir: &Path,
    retain: Option<usize>,
) -> Result<DirectoryBackup> {
    if !dir.is_dir() {
        bail!("backup directory {} does not exist", dir.display());
    }
    let layout = Layout::new(database)?;
    if identity(&fs::metadata(dir)?) == identity(&fs::metadata(&layout.dir)?) {
        bail!(
            "--output-dir must not be the database's directory ({}): give a directory of its own for backups",
            dir.display()
        );
    }
    let series = {
        use std::os::unix::fs::OpenOptionsExt;
        let lock = dir.join(".backup.lock");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock)
            .with_context(|| format!("open {}", lock.display()))?;
        if rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err() {
            bail!("another backup into {} is running", dir.display());
        }
        file
    };
    let mut index = read_index(dir)?;
    let source_path = fs::canonicalize(database)?;
    let _read = read_guard(database)?;
    let store = Store::open_read_only(database, master_key)?;
    let created_unix = now();
    let file = format!("backup-{}.sqlite", compact_utc(created_unix));
    let path = dir.join(&file);
    store.backup(&path)?;
    drop(store);
    // Verify what was published, as a restore would read it.
    let verification = Store::open_read_only(&path, master_key)?.verify()?;
    // Read-only, so it cannot be served in place by mistake (SQLite refuses
    // every write), which also keeps retention clear of writers.
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        fs::File::open(&path)?.sync_all()?;
    }
    let metadata = fs::metadata(&path)?;
    let content = witness(&path)?;
    index.backups.push(IndexedBackup {
        file: file.clone(),
        source: source_path.clone(),
        bytes: content.bytes,
        sha256: content.sha256,
        created_unix,
    });
    // Forget entries whose files are gone (pruned by a run that was killed
    // before rewriting the index, or removed by hand).
    index.backups.retain(|entry| dir.join(&entry.file).exists());
    write_index(dir, &index)?;
    let mut planned = vec![];
    if let Some(keep) = retain {
        let mut ours: Vec<IndexedBackup> = index
            .backups
            .iter()
            .filter(|entry| entry.source == source_path && entry.file != file)
            .cloned()
            .collect();
        ours.sort_by(|a, b| a.file.cmp(&b.file));
        let excess = (ours.len() + 1).saturating_sub(keep);
        planned = ours.into_iter().take(excess).collect();
    }
    let mut report = DirectoryBackup {
        file,
        path,
        bytes: metadata.len(),
        created: rfc3339_utc(created_unix),
        created_unix,
        verified: true,
        verification,
        pruned: planned.iter().map(|entry| entry.file.clone()).collect(),
        kept: vec![],
        unrecorded: vec![],
    };
    // The manifest names the new backup before any older one goes, so it
    // never points at a deleted file.
    let publish = |report: &DirectoryBackup| -> Result<()> {
        let mut json = serde_json::to_vec_pretty(report)?;
        json.push(b'\n');
        write_replacing(&dir.join("latest.json"), &json)
    };
    publish(&report)?;
    fault("backup-published");
    let mut pruned = vec![];
    for entry in &planned {
        match prune_one(dir, entry)? {
            Ok(()) => pruned.push(entry.file.clone()),
            Err(reason) => report.kept.push(format!("{}: {reason}", entry.file)),
        }
    }
    sync_dir(dir)?;
    index.backups.retain(|entry| !pruned.contains(&entry.file));
    write_index(dir, &index)?;
    if retain.is_some() {
        for entry in fs::read_dir(dir)? {
            let Ok(name) = entry?.file_name().into_string() else {
                continue;
            };
            if backup_name(&name) && !index.backups.iter().any(|e| e.file == name) {
                report.unrecorded.push(name);
            }
        }
        report.unrecorded.sort();
    }
    report.pruned = pruned;
    if !report.kept.is_empty() {
        publish(&report)?;
    }
    drop(series);
    Ok(report)
}

/// Why the database must not be opened now: a cutover that `restore` or
/// `rotate-master-key --in-place` (with or without `--revert`) began and did
/// not finish, during which the database may be missing or half moved. Only
/// the intent records those commands write count, each named after the
/// database (`<database>.restore.json`, `.rotation.json`, `.revert.json`),
/// so directories made by hand or by scripts never do. With
/// `restores_only`, only an unfinished restore counts.
pub fn unfinished_maintenance(database: &Path, restores_only: bool) -> Result<Option<String>> {
    let layout = Layout::new(database)?;
    let intent = layout.restore_intent();
    if exists(&intent)? {
        let id = read_record::<RestoreIntent>(&intent)?;
        let id = match &id {
            Record::Valid(intent) => intent.id.as_str(),
            _ => "?",
        };
        return Ok(Some(format!(
            "restore {id} of {} is unfinished ({} exists): run the same restore again, with --id {id}, to finish it",
            layout.database.display(),
            intent.display()
        )));
    }
    if !restores_only {
        for (record, what) in [
            (layout.rotation_journal(), "an in-place master-key rotation"),
            (layout.revert_journal(), "a revert of an in-place rotation"),
        ] {
            if exists(&record)? {
                return Ok(Some(format!(
                    "{what} of {} is unfinished ({} exists): run rotate-master-key --in-place again (with --revert for a revert, or to undo the rotation)",
                    layout.database.display(),
                    record.display()
                )));
            }
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------- restore

/// `restore` arguments.
pub struct Restore<'a> {
    pub from: &'a Path,
    pub id: &'a str,
    pub database: &'a Path,
    pub master_key: &'a Path,
    pub audit_checkpoint: Option<&'a Path>,
}

/// Restore identifiers name files: 1-64 of `A-Za-z0-9._-`, not starting
/// with `.` or `-`.
pub fn valid_restore_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !id.starts_with(['.', '-'])
}

fn verify_candidate(
    path: &Path,
    master_key: &Path,
    checkpoint: Option<&Path>,
) -> Result<Verification> {
    let store = Store::open_read_only(path, master_key)?;
    let verification = store.verify()?;
    if let Some(checkpoint) = checkpoint {
        store.verify_audit_checkpoint(checkpoint)?;
    }
    Ok(verification)
}

/// The intent record of a restore (`<database>.restore.json`). It is
/// published once the staged copy has passed every check (key, integrity,
/// checkpoint), before any database file moves, and removed after the
/// completion marker. `copy` is the staged copy's size and SHA-256, which
/// no rename or remount changes, so a retry knows the copy (staged or
/// installed) by its content; `source` is the backup's, for the marker.
/// Once anything has moved, a restore whose record exists only moves
/// forward; while nothing has, a run that cannot proceed removes it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreIntent {
    id: String,
    from: PathBuf,
    copy: Witness,
    source: Witness,
}

/// The paths of restore `id` of the database.
struct RestorePaths {
    marker: PathBuf,
    previous: PathBuf,
    staged: PathBuf,
}

impl RestorePaths {
    fn new(layout: &Layout, id: &str) -> Self {
        Self {
            marker: layout.dir.join(format!(".restore-{id}")),
            previous: layout.dir.join(format!("pre-restore-{id}")),
            staged: layout.dir.join(format!(".restore-{id}.sqlite.tmp")),
        }
    }
}

/// Verify a backup and install it as the database. See the module comment
/// for the files. Everything is verified (key, integrity, checkpoint) before
/// the cutover begins; once files have moved, the restore only moves
/// forward. A completed id is a no-op (for the same backup), and an
/// interrupted one is completed by running it again.
pub fn restore(r: &Restore<'_>) -> Result<Outcome> {
    if !valid_restore_id(r.id) {
        bail!(
            "invalid restore id {:?}: use 1-64 letters, digits, '.', '_' or '-', not starting with '.' or '-'",
            r.id
        );
    }
    let layout = Layout::new(r.database)?;
    let paths = RestorePaths::new(&layout, r.id);
    let target = fs::canonicalize(&layout.dir)?.join(&layout.name);
    if exists(&paths.marker)? && !exists(&layout.restore_intent())? {
        return completed_restore(r, &layout, &paths, &target, false);
    }
    if exists(&layout.restore_intent())? {
        let _lock = WriterLock::acquire(r.database, "restore")?;
        let _cutover = CutoverLock::acquire(&layout)?;
        return settled(r.database, resume_restore(r, &layout, &target)?);
    }
    if exists(&paths.previous)? {
        bail!(
            "{} already exists and was not made by restore {}: give this restore another --id",
            paths.previous.display(),
            r.id
        );
    }
    // 1. Verify the backup where it is, read-only; nothing changes on failure.
    if !fs::symlink_metadata(r.from)
        .with_context(|| format!("backup {}", r.from.display()))?
        .is_file()
    {
        bail!("backup {} must be a regular file", r.from.display());
    }
    if fs::metadata(sidecar(r.from, "-wal")).is_ok_and(|m| m.len() > 0) {
        bail!(
            "backup {} has a non-empty -wal file: restore a standalone copy written by `backup`",
            r.from.display()
        );
    }
    let from = fs::canonicalize(r.from)?;
    if from == target {
        bail!("--from is the database itself");
    }
    let verified = verify_candidate(r.from, r.master_key, r.audit_checkpoint)
        .with_context(|| format!("verify backup {}", r.from.display()))?;
    let source = witness(r.from)?;
    // 2. Under the writer and cutover locks, stage a private copy and verify
    //    it again.
    let _lock = WriterLock::acquire(r.database, "restore")?;
    let _cutover = CutoverLock::acquire(&layout)?;
    if exists(&layout.restore_intent())? {
        return settled(r.database, resume_restore(r, &layout, &target)?);
    }
    if exists(&paths.marker)? {
        return completed_restore(r, &layout, &paths, &target, true);
    }
    if exists(&paths.previous)? {
        bail!(
            "{} already exists and was not made by restore {}: give this restore another --id",
            paths.previous.display(),
            r.id
        );
    }
    if let Some(unfinished) = unfinished_maintenance(r.database, false)? {
        bail!("{unfinished}; this restore changed nothing");
    }
    remove_stale_staging(&layout.dir)?;
    Layout::remove_family_of(&paths.staged)?;
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut copy = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&paths.staged)
            .with_context(|| format!("create {}", paths.staged.display()))?;
        std::io::copy(&mut fs::File::open(r.from)?, &mut copy)?;
        copy.sync_all()?;
    }
    let staged = (|| -> Result<(Verification, Witness)> {
        if witness(&paths.staged)? != source {
            bail!("the backup changed while it was copied");
        }
        if require_rollback_journal(&paths.staged).is_err() {
            // A WAL-mode copy whose WAL is empty: make it standalone, so the
            // installed file depends on no sidecar.
            rusqlite::Connection::open(&paths.staged)?.pragma_update(
                None,
                "journal_mode",
                "DELETE",
            )?;
            require_rollback_journal(&paths.staged)?;
            fs::File::open(&paths.staged)?.sync_all()?;
        }
        let verification = verify_candidate(&paths.staged, r.master_key, r.audit_checkpoint)?;
        if verification != verified {
            bail!("the backup changed while it was copied");
        }
        // The cutover must be able to move the database's files.
        refuse_file_mounts(&layout)?;
        Ok((verification, witness(&paths.staged)?))
    })();
    let (verification, copy) = match staged {
        Ok(staged) => staged,
        Err(error) => {
            let _ = Layout::remove_family_of(&paths.staged);
            return Err(error.context("prepare the restore"));
        }
    };
    // 3. Record the intent, move the current database aside and install the
    //    copy.
    let intent = RestoreIntent {
        id: r.id.into(),
        from: r.from.to_path_buf(),
        copy,
        source,
    };
    publish_new(
        &layout.restore_intent(),
        &serde_json::to_vec(&intent)?,
        "restore-intent-staged",
    )?;
    fault("restore-recorded");
    let moved = cutover(&layout, &paths)?;
    finish_restore(r, &layout, &paths, &target, &verification, &intent)?;
    let mut messages = vec![format!(
        "Verified backup {}: {} objects, {} audit entries{}",
        r.from.display(),
        verification.objects,
        verification.audit_entries,
        if r.audit_checkpoint.is_some() {
            ", audit checkpoint passed"
        } else {
            ""
        }
    )];
    messages.push(if moved == 0 {
        format!(
            "Restored it as {} (restore {}); there was no database before",
            layout.database.display(),
            r.id
        )
    } else {
        format!(
            "Restored it as {} (restore {}); the previous database is in {}",
            layout.database.display(),
            r.id,
            paths.previous.display()
        )
    });
    messages.push(
        "Start the server with the master key that opened the backup; delete the previous database once the restore is confirmed".into(),
    );
    settled(
        r.database,
        Outcome {
            changed: true,
            messages,
        },
    )
}

/// Whether any of the database's files is in the previous-database
/// directory: the cutover has begun.
fn restore_began(layout: &Layout, paths: &RestorePaths) -> Result<bool> {
    for suffix in FAMILY {
        if exists(&layout.member(&paths.previous, suffix))? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The cutover of a staged restore: move the database family aside (main
/// file first) and rename the copy into place. Each step is skipped when an
/// earlier run did it. If it fails before anything has moved, the restore is
/// abandoned instead: the staged copy, the empty directory and the record go,
/// and the database is as it was. Returns how many files moved.
fn cutover(layout: &Layout, paths: &RestorePaths) -> Result<usize> {
    let attempt = || -> Result<usize> {
        refuse_file_mounts(layout)?;
        if !exists(&paths.previous)? {
            private_dir(&paths.previous)?;
            sync_dir(&layout.dir)?;
        }
        let moved = layout.move_family(&layout.dir, &paths.previous, "restore")?;
        install_staged(layout, paths)?;
        Ok(moved)
    };
    match attempt() {
        Ok(moved) => Ok(moved),
        Err(error) if exists(&paths.staged)? && !restore_began(layout, paths)? => {
            Layout::remove_family_of(&paths.staged)?;
            if exists(&paths.previous)? {
                let mut ignored = vec![];
                remove_if_empty(&paths.previous, &mut ignored)?;
            }
            remove_journal(&layout.restore_intent())?;
            bail!(
                "{error:#}. nothing was moved, so the restore was abandoned and its record removed: {} is as it was",
                layout.database.display()
            )
        }
        Err(error) => Err(error),
    }
}

fn install_staged(layout: &Layout, paths: &RestorePaths) -> Result<()> {
    if exists(&layout.database)? {
        bail!(
            "{} reappeared during the restore; the previous database is in {}",
            layout.database.display(),
            paths.previous.display()
        );
    }
    fs::rename(&paths.staged, &layout.database).with_context(|| {
        format!(
            "install {} as {}",
            paths.staged.display(),
            layout.database.display()
        )
    })?;
    sync_dir(&layout.dir)
}

/// Publish the completion marker, then drop the intent record.
fn finish_restore(
    r: &Restore<'_>,
    layout: &Layout,
    paths: &RestorePaths,
    target: &Path,
    verification: &Verification,
    intent: &RestoreIntent,
) -> Result<()> {
    let record = serde_json::json!({
        "id": r.id,
        "from": intent.from,
        "source": intent.source,
        "database": target,
        "installed": rfc3339_utc(now()),
        "previous": paths.previous,
        "objects": verification.objects,
        "audit_entries": verification.audit_entries,
    });
    publish_new(
        &paths.marker,
        format!("{record:#}\n").as_bytes(),
        "restore-marker-staged",
    )?;
    remove_journal(&layout.restore_intent())
}

/// A completed restore: its record must name this database and, when the
/// backup given is still there, this backup (by size and SHA-256); the
/// database must still be there, and a checkpoint given now must still
/// hold. `locked`: the caller holds the cutover lock, which excludes
/// readers, so the database is read without taking the read guard.
fn completed_restore(
    r: &Restore<'_>,
    layout: &Layout,
    paths: &RestorePaths,
    target: &Path,
    locked: bool,
) -> Result<Outcome> {
    #[derive(Deserialize)]
    struct Marker {
        database: PathBuf,
        #[serde(default)]
        from: Option<PathBuf>,
        #[serde(default)]
        source: Option<Witness>,
    }
    let marker_bytes =
        fs::read(&paths.marker).with_context(|| format!("read {}", paths.marker.display()))?;
    let record: Marker = serde_json::from_slice(&marker_bytes)
        .with_context(|| format!("{} is not a valid restore record", paths.marker.display()))?;
    if record.database != target {
        bail!(
            "restore id {} was used for {} in this directory: give this restore another --id",
            r.id,
            record.database.display()
        );
    }
    // The backup given now must be the one restored, by content. Only a
    // backup that is really gone (pruned since) is not checked; any other
    // error, or a path that is not a regular file, refuses.
    let given = match fs::symlink_metadata(r.from) {
        Ok(metadata) => Some(metadata),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!("backup {}", r.from.display())));
        }
    };
    if let Some(metadata) = &given
        && !metadata.is_file()
    {
        bail!("backup {} must be a regular file", r.from.display());
    }
    if let Some(source) = &record.source
        && let Some(metadata) = &given
    {
        let same = metadata.len() == source.bytes && witness(r.from)? == *source;
        if !same {
            bail!(
                "restore id {} was already used for {}: use a new id to restore {}",
                r.id,
                record
                    .from
                    .as_deref()
                    .unwrap_or(Path::new("another backup"))
                    .display(),
                r.from.display()
            );
        }
    }
    if !exists(&layout.database)? {
        bail!(
            "restore {} completed ({} exists), but {} does not exist",
            r.id,
            paths.marker.display(),
            layout.database.display()
        );
    }
    let mut messages = vec![format!(
        "Restore {} already completed ({} exists); nothing changed",
        r.id,
        paths.marker.display()
    )];
    if let Some(checkpoint) = r.audit_checkpoint {
        let _read = if locked {
            None
        } else {
            Some(read_guard(&layout.database)?)
        };
        verify_candidate(&layout.database, r.master_key, Some(checkpoint)).with_context(|| {
            format!(
                "restore {} completed, but {} no longer satisfies --audit-checkpoint",
                r.id,
                layout.database.display()
            )
        })?;
        messages.push(format!(
            "{} still satisfies the audit checkpoint",
            layout.database.display()
        ));
    }
    Ok(Outcome {
        changed: false,
        messages,
    })
}

/// Finish the restore that `<database>.restore.json` records, under the
/// locks. Its copy passed every check before the record was published, so
/// this only completes the cutover (`cutover`), publishes the marker and
/// drops the record. A checkpoint given now is checked after that, like a
/// completed restore's. The only refusals are a key that does not open the
/// copy (nothing changes; retry with the right key) and a copy whose
/// content is not the recorded one, which only outside interference can
/// cause; the error then says how to finish by hand.
fn resume_restore(r: &Restore<'_>, layout: &Layout, target: &Path) -> Result<Outcome> {
    let intent = match read_record::<RestoreIntent>(&layout.restore_intent())? {
        Record::Valid(intent) => intent,
        _ => bail!(
            "{} is unreadable: compare {} with the pre-restore-* directories next to it before removing anything",
            layout.restore_intent().display(),
            layout.database.display()
        ),
    };
    if intent.id != r.id {
        bail!(
            "restore {id} of {} is unfinished: run the same restore again with --id {id} to finish it; nothing changed",
            layout.database.display(),
            id = intent.id
        );
    }
    let paths = RestorePaths::new(layout, r.id);
    let by_hand = |problem: String| {
        anyhow::anyhow!(
            "{problem}. Restore {id} cannot finish on its own, and the server and the maintenance commands \
             refuse {database} until {record} is gone. To keep the current {database}: copy it (with \
             {database}-wal if there is one) into an empty directory of your own, run check-store on the \
             copy, and if it verifies delete {record}. To go back instead: move {database} and its -wal and \
             -shm files aside, move the files in {previous} into {dir}, and delete {record}",
            id = r.id,
            previous = paths.previous.display(),
            database = layout.database.display(),
            dir = layout.dir.display(),
            record = layout.restore_intent().display()
        )
    };
    if !exists(&paths.marker)? {
        let staged = exists(&paths.staged)?;
        let copy = if staged {
            &paths.staged
        } else {
            &layout.database
        };
        let recorded = fs::symlink_metadata(copy).is_ok_and(|m| m.len() == intent.copy.bytes)
            && witness(copy)? == intent.copy;
        if !recorded {
            return Err(by_hand(format!(
                "{} is not the copy restore {} recorded (its size or SHA-256 differs)",
                copy.display(),
                r.id
            )));
        }
        if !Store::master_key_opens(copy, r.master_key)? {
            bail!(
                "--master-key does not open {}, the copy restore {} installs: give the key you restored with; nothing changed",
                copy.display(),
                r.id
            );
        }
        let verification = Store::open_read_only(copy, r.master_key)
            .and_then(|store| store.verify())
            .map_err(|error| by_hand(format!("{error:#}: the copy no longer verifies")))?;
        if staged {
            cutover(layout, &paths)?;
        }
        finish_restore(r, layout, &paths, target, &verification, &intent)?;
    } else {
        // Killed after the marker, before the record went.
        remove_journal(&layout.restore_intent())?;
    }
    let mut messages = vec![format!(
        "Completed the interrupted restore {}: {} is the verified backup; the previous database is in {}",
        r.id,
        layout.database.display(),
        paths.previous.display()
    )];
    if let Some(checkpoint) = r.audit_checkpoint {
        verify_candidate(&layout.database, r.master_key, Some(checkpoint)).with_context(|| {
            format!(
                "restore {} completed, but {} does not satisfy --audit-checkpoint",
                r.id,
                layout.database.display()
            )
        })?;
        messages.push(format!(
            "{} satisfies the audit checkpoint",
            layout.database.display()
        ));
    }
    messages.push("Start the server with the master key that opened the backup".into());
    Ok(Outcome {
        changed: true,
        messages,
    })
}

// ------------------------------------------------------- in-place rotation

/// `rotate-master-key --in-place` arguments. `master_key` is the new key,
/// the one the server uses after the rotation.
pub struct InPlaceRotation<'a> {
    pub database: &'a Path,
    pub master_key: &'a Path,
    pub previous_master_key: &'a Path,
    pub audit_checkpoint: Option<&'a Path>,
    pub checkpoint_output: Option<&'a Path>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationJournal {
    pre: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevertJournal {
    pre: String,
    post: String,
}

enum Record<T> {
    Absent,
    Valid(T),
    /// Present but unreadable: written by a release that did not publish
    /// records atomically and was killed mid-write, or damaged.
    Torn,
}

fn read_record<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Record<T>> {
    match fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).map_or(Record::Torn, Record::Valid)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Record::Absent),
        Err(e) => Err(anyhow::Error::new(e).context(format!("read {}", path.display()))),
    }
}

fn remove_journal(path: &Path) -> Result<()> {
    fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    sync_dir(path.parent().unwrap_or(Path::new(".")))
}

/// The newest `pre-rotation-<time>` directory that holds the database.
fn latest_pre_rotation(layout: &Layout) -> Result<Option<PathBuf>> {
    let mut newest: Option<((String, u32), String)> = None;
    for entry in fs::read_dir(&layout.dir)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(key) = archive_key(&name, "pre-rotation-") else {
            continue;
        };
        if entry.file_type()?.is_dir()
            && layout.member(&entry.path(), "").is_file()
            && newest.as_ref().is_none_or(|(k, _)| key > *k)
        {
            newest = Some((key, name));
        }
    }
    Ok(newest.map(|(_, name)| layout.dir.join(name)))
}

enum Opens {
    New,
    Previous,
}

fn which_key(database: &Path, new: &Path, previous: &Path) -> Result<Opens> {
    if Store::master_key_opens(database, new)? {
        Ok(Opens::New)
    } else if Store::master_key_opens(database, previous)? {
        Ok(Opens::Previous)
    } else {
        bail!(
            "neither --master-key nor --previous-master-key opens {}; nothing changed",
            database.display()
        )
    }
}

/// Every command that writes a record ends by checking that none is left:
/// success is never reported while `serve` would still refuse to start.
/// Call it while still holding the writer and cutover locks, so no other
/// operation can have started in between.
fn settled(database: &Path, mut outcome: Outcome) -> Result<Outcome> {
    pause("settling");
    if let Some(unfinished) = unfinished_maintenance(database, false)? {
        bail!("{unfinished} (left by this run; please report it)");
    }
    outcome.messages.retain(|m| !m.is_empty());
    Ok(outcome)
}

/// Common start of `rotate_in_place` and `revert_in_place`: the writer lock,
/// no unfinished restore, stale staging removed, and a rotation record that
/// is torn (from a release that wrote records in place) dropped when it is
/// provably unused: its copy is still next to the untouched database.
fn begin(
    o: &InPlaceRotation<'_>,
    holder: &str,
) -> Result<(Layout, (WriterLock, CutoverLock), Vec<String>)> {
    distinct_keys(o.master_key, o.previous_master_key)?;
    let layout = Layout::new(o.database)?;
    let lock = WriterLock::acquire(o.database, holder)?;
    let cutover = CutoverLock::acquire(&layout)?;
    if let Some(unfinished) = unfinished_maintenance(o.database, true)? {
        bail!("{unfinished}; nothing changed");
    }
    remove_stale_staging(&layout.dir)?;
    let mut messages = vec![];
    if let Record::Torn = read_record::<RotationJournal>(&layout.rotation_journal())? {
        if exists(&layout.rotated())? && exists(&layout.database)? {
            Layout::remove_family_of(&layout.rotated())?;
            remove_journal(&layout.rotation_journal())?;
            messages.push(format!(
                "Discarded {} and the unreadable record {} of an interrupted run; its cutover had not begun",
                layout.rotated().display(),
                layout.rotation_journal().display()
            ));
        } else {
            bail!(
                "{} is unreadable and its cutover may have begun: compare {} with the pre-rotation-* directories next to it before removing anything",
                layout.rotation_journal().display(),
                layout.database.display()
            );
        }
    }
    Ok((layout, (lock, cutover), messages))
}

/// Rotate the database from `previous_master_key` to `master_key` in
/// place, or do nothing if it already opens with `master_key`.
pub fn rotate_in_place(o: &InPlaceRotation<'_>) -> Result<Outcome> {
    let (layout, locks, messages) = begin(o, "rotate-master-key")?;
    let outcome = settled(o.database, rotate_in_place_inner(o, &layout, messages)?)?;
    drop(locks);
    Ok(outcome)
}

fn rotate_in_place_inner(
    o: &InPlaceRotation<'_>,
    layout: &Layout,
    mut messages: Vec<String>,
) -> Result<Outcome> {
    let layout = layout.clone();
    match read_record::<RevertJournal>(&layout.revert_journal())? {
        Record::Absent => {}
        _ => bail!(
            "a revert was interrupted ({} exists): run rotate-master-key --in-place --revert again to finish it",
            layout.revert_journal().display()
        ),
    }
    let rotated = layout.rotated();
    if let Record::Valid(journal) = read_record::<RotationJournal>(&layout.rotation_journal())? {
        if stale_copy(o, &layout)? {
            // Nothing was moved yet, but the database changed after the copy
            // was written: drop the copy and the record, and rotate again.
            Layout::remove_family_of(&rotated)?;
            let pre = layout.dir.join(&journal.pre);
            if stamped(&journal.pre, "pre-rotation-") && exists(&pre)? {
                remove_if_empty(&pre, &mut messages)?;
            }
            remove_journal(&layout.rotation_journal())?;
            messages.push(format!(
                "Discarded {} from an interrupted run: the database changed after it was written",
                rotated.display()
            ));
        } else {
            let mut outcome = finish_cutover(o, &layout, &journal, None)?;
            messages.push(format!(
                "Resuming the interrupted cutover into {}",
                journal.pre
            ));
            messages.append(&mut outcome.messages);
            outcome.messages = messages;
            return Ok(outcome);
        }
    }
    if !exists(&layout.database)? {
        bail!("database {} does not exist", layout.database.display());
    }
    if let Opens::New = which_key(&layout.database, o.master_key, o.previous_master_key)? {
        let mut outcome = already_rotated(o, &layout)?;
        messages.append(&mut outcome.messages);
        outcome.messages = messages;
        return Ok(outcome);
    }
    if exists(&rotated)? {
        // Published by an earlier run that stopped before its cutover began;
        // the database may have changed since, so write it again.
        Layout::remove_family_of(&rotated)?;
        messages.push(format!(
            "Removed {} left by an interrupted run",
            rotated.display()
        ));
    }
    let source = Store::open_read_only(&layout.database, o.previous_master_key)
        .context("verify the store with --previous-master-key")?;
    if source.storage_schema() != STORAGE_SCHEMA {
        bail!(
            "the store uses storage schema {}, older than this release's {}: start the server once to upgrade it, then rotate",
            source.storage_schema(),
            STORAGE_SCHEMA
        );
    }
    let summary = source.rotate_master_key_checked(o.master_key, &rotated, o.audit_checkpoint)?;
    drop(source);
    let checked = (|| -> Result<()> {
        Store::open_read_only(&rotated, o.master_key)?.verify_integrity()?;
        if Store::master_key_opens(&rotated, o.previous_master_key)? {
            bail!("rotated copy unexpectedly opens with the previous key");
        }
        Ok(())
    })();
    if let Err(error) = checked {
        let _ = Layout::remove_family_of(&rotated);
        return Err(error.context("verify the rotated copy"));
    }
    // One operation name for both archives: the pre-rotation directory and
    // the post-rotation one a later revert would use, both unused.
    let stamp = compact_utc(now());
    let mut n = 1u32;
    let pre = loop {
        let pre = format!("pre-rotation-{stamp}-{n}");
        let post = format!("post-rotation-{stamp}-{n}");
        if !exists(&layout.dir.join(&pre))? && !exists(&layout.dir.join(&post))? {
            break pre;
        }
        n += 1;
    };
    if let Err(error) = refuse_file_mounts(&layout) {
        let _ = Layout::remove_family_of(&rotated);
        return Err(error);
    }
    let journal = RotationJournal { pre };
    publish_new(
        &layout.rotation_journal(),
        &serde_json::to_vec(&journal)?,
        "rotation-record-staged",
    )?;
    let mut outcome = finish_cutover(o, &layout, &journal, Some(summary))?;
    messages.append(&mut outcome.messages);
    outcome.messages = messages;
    Ok(outcome)
}

/// An interrupted cutover whose moves have not begun (the database is still
/// in place next to its rotated copy) and whose copy is no longer the
/// rotation of that database.
fn stale_copy(o: &InPlaceRotation<'_>, layout: &Layout) -> Result<bool> {
    if !exists(&layout.rotated())? || !exists(&layout.database)? {
        return Ok(false);
    }
    let old = Store::open_read_only(&layout.database, o.previous_master_key)
        .context("verify the store with --previous-master-key")?;
    let new = Store::open_read_only(&layout.rotated(), o.master_key)
        .context("verify the rotated copy with --master-key")?;
    new.verify_integrity()?;
    Ok(new.verify_rotation_of(&old, true).is_err())
}

/// Move the old database into `journal.pre`, install the rotated copy,
/// verify it, write the checkpoint output and remove the journal. Each step
/// is skipped when an earlier run finished it. Before anything is installed
/// or a checkpoint issued, the old store must satisfy `audit_checkpoint` and
/// the copy must be its rotation.
fn finish_cutover(
    o: &InPlaceRotation<'_>,
    layout: &Layout,
    journal: &RotationJournal,
    summary: Option<RotationSummary>,
) -> Result<Outcome> {
    if !stamped(&journal.pre, "pre-rotation-") {
        bail!(
            "{} names an invalid directory",
            layout.rotation_journal().display()
        );
    }
    let pre = layout.dir.join(&journal.pre);
    let rotated = layout.rotated();
    if exists(&rotated)? {
        // Not installed yet. If the main file is gone, an earlier run began
        // moving the old store: finish assembling it in `pre` first (every
        // database file still in the directory belongs to it).
        let moved_before = !exists(&layout.database)?;
        if moved_before {
            if !exists(&pre)? {
                private_dir(&pre)?;
                sync_dir(&layout.dir)?;
            }
            layout.move_family(&layout.dir, &pre, "rotation")?;
        }
        let old_dir = if moved_before { &pre } else { &layout.dir };
        let refuse = |error: anyhow::Error| {
            if moved_before {
                anyhow::anyhow!(
                    "{error:#}. Nothing was installed, but an earlier run moved the database into {}: run rotate-master-key --in-place --revert to put it back",
                    pre.display()
                )
            } else {
                anyhow::anyhow!(
                    "{error:#}. nothing changed: {} is still the database from before the rotation",
                    layout.database.display()
                )
            }
        };
        let check = || -> Result<()> {
            let old = Store::open_read_only(&layout.member(old_dir, ""), o.previous_master_key)
                .context("verify the database from before the rotation")?;
            old.verify_integrity()?;
            if let Some(checkpoint) = o.audit_checkpoint {
                old.verify_audit_checkpoint(checkpoint)?;
            }
            let new = Store::open_read_only(&rotated, o.master_key)
                .context("verify the rotated copy with --master-key")?;
            new.verify_integrity()?;
            new.verify_rotation_of(&old, true)
        };
        check().map_err(refuse)?;
        if !moved_before {
            // Nothing has moved yet: if the move cannot begin, drop the
            // record (the copy is then unused and removed by the next run).
            let first = || -> Result<()> {
                refuse_file_mounts(layout)?;
                if !exists(&pre)? {
                    private_dir(&pre)?;
                    sync_dir(&layout.dir)?;
                }
                layout.move_family(&layout.dir, &pre, "rotation")?;
                Ok(())
            };
            if let Err(error) = first() {
                if exists(&layout.database)? {
                    if exists(&pre)? {
                        let mut ignored = vec![];
                        remove_if_empty(&pre, &mut ignored)?;
                    }
                    remove_journal(&layout.rotation_journal())?;
                    bail!(
                        "{error:#}. nothing was moved, so the rotation record was removed: {} is still the database from before the rotation",
                        layout.database.display()
                    );
                }
                return Err(error);
            }
        }
        if exists(&layout.database)? {
            bail!(
                "{} reappeared during the cutover; the database from before the rotation is in {}",
                layout.database.display(),
                pre.display()
            );
        }
        fs::rename(&rotated, &layout.database).with_context(|| {
            format!(
                "install {} as {}",
                rotated.display(),
                layout.database.display()
            )
        })?;
        sync_dir(&layout.dir)?;
        fault("rotation-installed");
    } else {
        if !exists(&layout.database)? {
            bail!(
                "interrupted rotation: neither {} nor {} exists. The database from before the rotation is in {}; move it back, delete {}, and run again",
                rotated.display(),
                layout.database.display(),
                pre.display(),
                layout.rotation_journal().display()
            );
        }
        // An earlier run installed the copy: check it before issuing a
        // checkpoint for it. The floor may be either key generation's.
        let check = || -> Result<()> {
            let old = Store::open_read_only(&layout.member(&pre, ""), o.previous_master_key)
                .with_context(|| format!("verify the pre-rotation copy in {}", pre.display()))?;
            old.verify_integrity()?;
            let new = Store::open_read_only(&layout.database, o.master_key)
                .context("verify the installed database with --master-key")?;
            new.verify_integrity()?;
            new.verify_rotation_of(&old, false)?;
            if let Some(checkpoint) = o.audit_checkpoint
                && new.verify_audit_checkpoint(checkpoint).is_err()
            {
                old.verify_audit_checkpoint(checkpoint)?;
            }
            Ok(())
        };
        check().map_err(|error| {
            anyhow::anyhow!(
                "{error:#}. An earlier run already installed the rotated database as {}; no checkpoint was issued. Run rotate-master-key --in-place --revert to put back the database from {}",
                layout.database.display(),
                pre.display()
            )
        })?;
    }
    let store = Store::open_read_only(&layout.database, o.master_key)?;
    let verification = store.verify()?;
    let mut messages = vec![];
    if let Some(summary) = summary {
        messages.push(format!(
            "Verified rotated snapshot: {} objects, {} audit entries",
            summary.objects, summary.audit_entries
        ));
    }
    messages.push(format!(
        "Rotated {} to --master-key ({} objects, {} audit entries); the database from before the rotation is in {}",
        layout.database.display(),
        verification.objects,
        verification.audit_entries,
        pre.display()
    ));
    if let Some(output) = o.checkpoint_output {
        ensure_checkpoint(&store, output, None, &mut messages)?;
    } else if o.audit_checkpoint.is_some() {
        messages.push(
            "The audit checkpoint belongs to the previous master key and no longer verifies the store: export one for --master-key (--checkpoint-output) before the server starts with a checkpoint".into(),
        );
    }
    drop(store);
    remove_journal(&layout.rotation_journal())?;
    messages.push(
        "Keep the previous key and the pre-rotation copy until no recovery needs them; take a backup under the new key".into(),
    );
    Ok(Outcome {
        changed: true,
        messages,
    })
}

/// The store already opens with the new key: verify it, and its checkpoint.
/// A checkpoint of the previous key generation is accepted when the newest
/// pre-rotation copy satisfies it and the store is that copy's rotation;
/// then `checkpoint_output` receives one for the new key.
fn already_rotated(o: &InPlaceRotation<'_>, layout: &Layout) -> Result<Outcome> {
    let store = Store::open_read_only(&layout.database, o.master_key)?;
    store.verify_integrity()?;
    let mut messages =
        vec!["The store already opens with --master-key; nothing to rotate".to_string()];
    if exists(&layout.rotated())? {
        messages.push(format!(
            "{} is not used by this store; delete it",
            layout.rotated().display()
        ));
    }
    let Some(checkpoint) = o.audit_checkpoint else {
        if let Some(output) = o.checkpoint_output {
            ensure_checkpoint(&store, output, None, &mut messages)?;
        }
        return Ok(Outcome {
            changed: false,
            messages,
        });
    };
    let current = match store.verify_audit_checkpoint(checkpoint) {
        Ok(()) => {
            if let Some(output) = o.checkpoint_output {
                ensure_checkpoint(&store, output, Some(checkpoint), &mut messages)?;
            }
            return Ok(Outcome {
                changed: false,
                messages,
            });
        }
        Err(error) => error,
    };
    let previous_generation = (|| -> Result<PathBuf> {
        let pre = latest_pre_rotation(layout)?.context("no pre-rotation copy")?;
        let old = Store::open_read_only(&layout.member(&pre, ""), o.previous_master_key)?;
        old.verify_integrity()?;
        old.verify_audit_checkpoint(checkpoint)?;
        store.verify_rotation_of(&old, false)?;
        Ok(pre)
    })();
    let Ok(pre) = previous_generation else {
        return Err(current.context(format!(
            "audit checkpoint {} does not verify the store",
            checkpoint.display()
        )));
    };
    let Some(output) = o.checkpoint_output else {
        bail!(
            "audit checkpoint {} belongs to the master key before the rotation (it verifies {}), and the server refuses it: give --checkpoint-output to write one for --master-key, and start the server with that",
            checkpoint.display(),
            pre.display()
        );
    };
    messages.push(format!(
        "Audit checkpoint {} belongs to the previous master key; it verifies the pre-rotation copy {}, of which this store is the rotation",
        checkpoint.display(),
        pre.display()
    ));
    ensure_checkpoint(&store, output, None, &mut messages)?;
    Ok(Outcome {
        changed: false,
        messages,
    })
}

/// The revert candidate: `pre`'s database opens with the previous key,
/// satisfies `audit_checkpoint`, and the rotated database at `rotated` (under
/// the new key) is its rotation.
fn verify_revert(
    o: &InPlaceRotation<'_>,
    layout: &Layout,
    pre: &Path,
    rotated: &Path,
) -> Result<()> {
    let old = Store::open_read_only(&layout.member(pre, ""), o.previous_master_key)
        .with_context(|| format!("verify {} with --previous-master-key", pre.display()))?;
    old.verify_integrity()?;
    if let Some(checkpoint) = o.audit_checkpoint {
        old.verify_audit_checkpoint(checkpoint)?;
    }
    let new = Store::open_read_only(rotated, o.master_key)
        .with_context(|| format!("verify {} with --master-key", rotated.display()))?;
    new.verify_integrity()?;
    new.verify_rotation_of(&old, false)
}

/// Put back the newest pre-rotation database (under the previous key) and
/// move the rotated one to `post-rotation-<time>`, or finish such a revert.
pub fn revert_in_place(o: &InPlaceRotation<'_>) -> Result<Outcome> {
    let (layout, locks, messages) = begin(o, "rotate-master-key --revert")?;
    let outcome = settled(o.database, revert_in_place_inner(o, &layout, messages)?)?;
    drop(locks);
    Ok(outcome)
}

fn revert_in_place_inner(
    o: &InPlaceRotation<'_>,
    layout: &Layout,
    mut messages: Vec<String>,
) -> Result<Outcome> {
    let layout = layout.clone();
    match read_record::<RevertJournal>(&layout.revert_journal())? {
        Record::Valid(journal) => {
            let mut outcome = finish_revert(o, &layout, &journal)?;
            messages.push("Resuming the interrupted revert".into());
            messages.append(&mut outcome.messages);
            outcome.messages = messages;
            return Ok(outcome);
        }
        Record::Torn => bail!(
            "{} is unreadable: compare {} with the pre-rotation-* and post-rotation-* directories next to it before removing anything",
            layout.revert_journal().display(),
            layout.database.display()
        ),
        Record::Absent => {}
    }
    let rotation = match read_record::<RotationJournal>(&layout.rotation_journal())? {
        Record::Valid(journal) => Some(journal),
        _ => None,
    };
    if let Some(journal) = &rotation
        && exists(&layout.rotated())?
    {
        let mut outcome = undo_cutover(o, &layout, journal)?;
        messages.append(&mut outcome.messages);
        outcome.messages = messages;
        return Ok(outcome);
    }
    if !exists(&layout.database)? {
        bail!("database {} does not exist", layout.database.display());
    }
    if let Opens::Previous = which_key(&layout.database, o.master_key, o.previous_master_key)? {
        let store = Store::open_read_only(&layout.database, o.previous_master_key)?;
        store.verify_integrity()?;
        messages.push(
            "The store already opens with --previous-master-key; nothing to revert".to_string(),
        );
        if exists(&layout.rotated())? {
            Layout::remove_family_of(&layout.rotated())?;
            messages.push(format!(
                "Removed {}, an unused rotated copy",
                layout.rotated().display()
            ));
        }
        checkpoint_for(&store, o, &mut messages)?;
        return Ok(Outcome {
            changed: false,
            messages,
        });
    }
    let pre = match &rotation {
        Some(journal) => layout.dir.join(&journal.pre),
        None => latest_pre_rotation(&layout)?.context("no pre-rotation copy to revert to")?,
    };
    let pre_name = pre
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| stamped(n, "pre-rotation-"))
        .context("invalid pre-rotation directory")?
        .to_string();
    verify_revert(o, &layout, &pre, &layout.database)
        .map_err(|error| anyhow::anyhow!("{error:#}. nothing changed"))?;
    let post = format!("post-rotation-{}", &pre_name["pre-rotation-".len()..]);
    if exists(&layout.dir.join(&post))? {
        bail!("{} already exists", layout.dir.join(&post).display());
    }
    refuse_file_mounts(&layout)?;
    let journal = RevertJournal {
        pre: pre_name,
        post,
    };
    publish_new(
        &layout.revert_journal(),
        &serde_json::to_vec(&journal)?,
        "revert-record-staged",
    )?;
    fault("revert-recorded");
    if rotation.is_some() {
        remove_journal(&layout.rotation_journal())?;
    }
    let mut outcome = finish_revert(o, &layout, &journal)?;
    messages.append(&mut outcome.messages);
    outcome.messages = messages;
    Ok(outcome)
}

/// Remove a directory the database family was moved out of; keep it, with
/// a message, if it holds anything else.
fn remove_if_empty(dir: &Path, messages: &mut Vec<String>) -> Result<()> {
    if fs::read_dir(dir)?.next().is_none() {
        fs::remove_dir(dir).with_context(|| format!("remove {}", dir.display()))?;
    } else {
        messages.push(format!(
            "Kept {}: it holds files other than the database",
            dir.display()
        ));
    }
    Ok(())
}

fn checkpoint_for(
    store: &Store,
    o: &InPlaceRotation<'_>,
    messages: &mut Vec<String>,
) -> Result<()> {
    if let Some(checkpoint) = o.audit_checkpoint {
        store.verify_audit_checkpoint(checkpoint)?;
    }
    if let Some(output) = o.checkpoint_output {
        ensure_checkpoint(store, output, o.audit_checkpoint, messages)?;
    }
    Ok(())
}

/// Step 1 moves the rotated family to `post`, step 2 moves `pre`'s family
/// back, main files first. The candidate is verified before step 2 begins;
/// when a check fails after an earlier run already moved live files, the
/// error says so.
fn finish_revert(
    o: &InPlaceRotation<'_>,
    layout: &Layout,
    journal: &RevertJournal,
) -> Result<Outcome> {
    if !stamped(&journal.pre, "pre-rotation-") || !stamped(&journal.post, "post-rotation-") {
        bail!(
            "{} names an invalid directory",
            layout.revert_journal().display()
        );
    }
    let pre = layout.dir.join(&journal.pre);
    let post = layout.dir.join(&journal.post);
    let mut messages = vec![];
    if layout.member(&pre, "").is_file() {
        // Step 2 has not begun. If the rotated main file is already in
        // `post`, an earlier run began step 1: finish assembling it there.
        let aside_before = exists(&layout.member(&post, ""))?;
        if aside_before {
            layout.move_family(&layout.dir, &post, "revert-aside")?;
        }
        let rotated = layout.member(if aside_before { &post } else { &layout.dir }, "");
        if let Err(error) = verify_revert(o, layout, &pre, &rotated) {
            if aside_before {
                bail!(
                    "{error:#}. An earlier run already moved the rotated database to {post}, so {database} is missing: \
                     run the revert again without the rejecting checkpoint, or move the files in {post} back into {dir} \
                     and delete {record} to return to the rotated database",
                    post = post.display(),
                    database = layout.database.display(),
                    dir = layout.dir.display(),
                    record = layout.revert_journal().display()
                );
            }
            // Nothing has moved: drop the record so the store stays usable.
            remove_journal(&layout.revert_journal())?;
            bail!(
                "{error:#}. nothing changed: {} is still the rotated database, and the revert record was removed",
                layout.database.display()
            );
        }
        if !aside_before {
            let first = || -> Result<()> {
                refuse_file_mounts(layout)?;
                if !exists(&post)? {
                    private_dir(&post)?;
                    sync_dir(&layout.dir)?;
                }
                layout.move_family(&layout.dir, &post, "revert-aside")?;
                Ok(())
            };
            if let Err(error) = first() {
                if exists(&layout.database)? {
                    if exists(&post)? {
                        let mut ignored = vec![];
                        remove_if_empty(&post, &mut ignored)?;
                    }
                    remove_journal(&layout.revert_journal())?;
                    bail!(
                        "{error:#}. nothing was moved, so the revert record was removed: {} is still the rotated database",
                        layout.database.display()
                    );
                }
                return Err(error);
            }
        }
        layout.move_family(&pre, &layout.dir, "revert-back")?;
    } else {
        // Step 2 began in an earlier run: finish it, then check what it put
        // back.
        if exists(&pre)? {
            layout.move_family(&pre, &layout.dir, "revert-back")?;
        }
        let check = || -> Result<()> {
            let old = Store::open_read_only(&layout.database, o.previous_master_key)
                .context("verify the reverted store with --previous-master-key")?;
            old.verify_integrity()?;
            if let Some(checkpoint) = o.audit_checkpoint {
                old.verify_audit_checkpoint(checkpoint)?;
            }
            let new = Store::open_read_only(&layout.member(&post, ""), o.master_key)
                .context("verify the rotated database with --master-key")?;
            new.verify_integrity()?;
            new.verify_rotation_of(&old, false)
        };
        check().map_err(|error| {
            anyhow::anyhow!(
                "{error:#}. An earlier run already put back the database from before the rotation as {} (the rotated database is in {})",
                layout.database.display(),
                post.display()
            )
        })?;
    }
    if exists(&pre)? {
        remove_if_empty(&pre, &mut messages)?;
    }
    sync_dir(&layout.dir)?;
    let store = Store::open_read_only(&layout.database, o.previous_master_key)
        .context("verify the reverted store with --previous-master-key")?;
    store.verify_integrity()?;
    messages.insert(0, format!(
        "Reverted {} to the database from before the rotation, under --previous-master-key; the rotated database is in {}",
        layout.database.display(),
        post.display()
    ));
    checkpoint_for(&store, o, &mut messages)?;
    drop(store);
    // The rotation record this revert superseded, if a run was killed
    // before removing it; then the revert's own.
    if exists(&layout.rotation_journal())? {
        remove_journal(&layout.rotation_journal())?;
    }
    remove_journal(&layout.revert_journal())?;
    messages.push(
        "Start the server with the previous master key (and its audit checkpoint); writes accepted since the rotation are not carried back".into(),
    );
    Ok(Outcome {
        changed: true,
        messages,
    })
}

/// A rotation stopped before its copy was installed: put the old files
/// back, check them, then drop the copy and the record.
fn undo_cutover(
    o: &InPlaceRotation<'_>,
    layout: &Layout,
    journal: &RotationJournal,
) -> Result<Outcome> {
    if !stamped(&journal.pre, "pre-rotation-") {
        bail!(
            "{} names an invalid directory",
            layout.rotation_journal().display()
        );
    }
    let pre = layout.dir.join(&journal.pre);
    let mut messages = vec![];
    if exists(&pre)? {
        layout.move_family(&pre, &layout.dir, "undo")?;
        remove_if_empty(&pre, &mut messages)?;
    }
    sync_dir(&layout.dir)?;
    let store = Store::open_read_only(&layout.database, o.previous_master_key)
        .context("verify the store with --previous-master-key")?;
    store.verify_integrity()?;
    // The files are back as they were before the rotation; keep the copy
    // and the record (and so keep the server stopped) if the floor fails.
    checkpoint_for(&store, o, &mut messages).map_err(|error| {
        anyhow::anyhow!(
            "{error:#}. {} is back as it was before the rotation; {} and {} are kept",
            layout.database.display(),
            layout.rotated().display(),
            layout.rotation_journal().display()
        )
    })?;
    drop(store);
    // The record goes first: a copy left without one is unused and removed
    // by the next run of either direction.
    remove_journal(&layout.rotation_journal())?;
    fault("undo-record-removed");
    Layout::remove_family_of(&layout.rotated())?;
    sync_dir(&layout.dir)?;
    messages.insert(0, format!(
        "Reverted an interrupted rotation: {} is the database from before it, under --previous-master-key",
        layout.database.display()
    ));
    Ok(Outcome {
        changed: true,
        messages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formats_match_known_instants() {
        assert_eq!(compact_utc(0), "19700101T000000Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(compact_utc(1_793_844_900), "20261105T021500Z");
        assert_eq!(rfc3339_utc(4_107_542_399), "2100-02-28T23:59:59Z");
        assert!(stamped("pre-rotation-20261105T021500Z", "pre-rotation-"));
        assert!(!stamped("pre-rotation-20261105T021500", "pre-rotation-"));
        assert!(!stamped("pre-rotation-2026110xT021500Z", "pre-rotation-"));
        assert!(backup_name("backup-20261105T021500Z.sqlite"));
        assert!(!backup_name("backup-20261105T021500Z.sqlite-wal"));
        assert!(!backup_name("kmip.sqlite"));
        assert!(!backup_name("backup-latest.sqlite"));
    }

    #[test]
    fn restore_ids_name_files_safely() {
        assert!(valid_restore_id("2026-11-05.1"));
        assert!(valid_restore_id("a"));
        for bad in ["", ".x", "-x", "a/b", "a b", "..", &"x".repeat(65)] {
            assert!(!valid_restore_id(bad), "{bad}");
        }
    }
}
