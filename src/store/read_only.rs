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

//! Read-only opens for the maintenance commands (`check-store`, `backup`,
//! `audit-checkpoint`, and the verification steps of `restore` and in-place
//! rotation). They never migrate, create tables or change the journal mode.
//!
//! SQLite and WAL: the connection uses `SQLITE_OPEN_READONLY`. A WAL reader
//! must take part in the WAL-index protocol through the `-shm` file, or it
//! cannot see a consistent snapshot while the server writes. So a read-only
//! connection still opens `-shm` (read-write if it may, otherwise SQLite's
//! read-only shared-memory mode), and when the server is stopped and no `-wal`
//! file exists, SQLite creates an empty `-wal` and a `-shm` next to the
//! database and leaves them. Neither changes the database: the reader never
//! appends frames, checkpoints or truncates the WAL. (So "read-only" means
//! the database's content and the main file are never written; empty
//! sidecars may appear.)
//!
//! Only when the directory does not allow those files to be created (a
//! read-only mount) does the open fall back to `immutable=1`, which reads the
//! main file with no SQLite locking at all. That is safe only while nothing
//! writes, so the fallback requires the writer lock file (`lock.rs`) and holds
//! a shared lock on it for the life of the store: no lock-respecting writer
//! (`serve`, `restore`, rotation) can start meanwhile. Under that lock it then
//! requires the `-wal` to be absent or empty (immutable would ignore committed
//! frames), and checks again after verification. Without a lock file the
//! fallback is refused.
use super::*;
use rusqlite::{ErrorCode, OpenFlags};

/// What a full verification covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verification {
    /// The store's schema (`PRAGMA user_version`).
    pub storage_schema: i32,
    pub objects: u64,
    pub audit_entries: u64,
    /// False for a store older than this binary: every object record and the
    /// audit chain were authenticated, but the store has no authenticated
    /// object index (inventory) yet.
    pub object_index_verified: bool,
}

/// The path with a suffix appended to its file name (`kmip.sqlite-wal`).
pub(crate) fn sidecar(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

/// Percent-encode a path for an SQLite `file:` URI.
fn uri_path(path: &Path) -> Result<String> {
    use std::fmt::Write;
    let text = path.to_str().context("database path must be UTF-8")?;
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"/._-~".contains(&byte) {
            out.push(byte as char);
        } else {
            write!(out, "%{byte:02X}")?;
        }
    }
    Ok(out)
}

/// Database header bytes 18 and 19 are 2 for WAL mode and 1 for a rollback
/// journal. `VACUUM INTO` writes rollback-journal files; refuse anything else
/// as a published standalone copy.
pub(crate) fn require_rollback_journal(path: &Path) -> Result<()> {
    use std::io::Read;
    let mut header = [0u8; 20];
    fs::File::open(path)?.read_exact(&mut header)?;
    if header[18] != 1 || header[19] != 1 {
        bail!("copy is not a standalone rollback-journal database");
    }
    Ok(())
}

/// A read-only connection; see the module comment.
fn connect_read_only(path: &Path) -> Result<(Connection, Option<fs::File>)> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    // The first read opens the WAL and -shm files if the database uses WAL.
    let error = match conn.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |r| {
        r.get::<_, i64>(0)
    }) {
        Ok(_) => return Ok((conn, None)),
        Err(error) => error,
    };
    let unwritable = matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::ReadOnly | ErrorCode::CannotOpen)
    );
    if !unwritable || wal_frames(path)? {
        return Err(anyhow::Error::new(error).context("open the database read-only"));
    }
    drop(conn);
    // The lock first, then the WAL state it protects.
    let lock = WriterLock::shared(path)?;
    if wal_frames(path)? {
        bail!(
            "{} has committed transactions in its -wal file and its directory is read-only: mount the directory read-write to read it",
            path.display()
        );
    }
    let uri = format!("file:{}?mode=ro&immutable=1", uri_path(path)?);
    let conn = Connection::open_with_flags(uri, flags | OpenFlags::SQLITE_OPEN_URI)?;
    conn.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |r| {
        r.get::<_, i64>(0)
    })
    .context("open the database read-only")?;
    Ok((conn, Some(lock)))
}

/// Whether the database's `-wal` file exists and holds anything.
fn wal_frames(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(sidecar(path, "-wal")) {
        Ok(metadata) => Ok(metadata.len() > 0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

impl Store {
    /// Open an existing store without changing it: no migration, no new
    /// tables, no journal-mode change, no write to the database (SQLite may
    /// create empty `-wal` and `-shm` files next to a stopped one). An older store (schema
    /// below `STORAGE_SCHEMA`) is verified as far as its schema allows: the
    /// key, the audit chain and every object record, but not an object index,
    /// which it does not have yet. A newer store is refused.
    pub fn open_read_only(path: &Path, master_key: &Path) -> Result<Self> {
        let key = Self::read_master_key(master_key)?;
        Self::open_read_only_with_key(path, key)
    }

    pub(crate) fn open_read_only_with_key(path: &Path, key: Zeroizing<Vec<u8>>) -> Result<Self> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!("database {} does not exist", path.display())
            }
            Err(e) => return Err(e.into()),
        };
        if !metadata.is_file() {
            bail!("database must be a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o007 != 0 {
                bail!("database must not be accessible to other users");
            }
        }
        let (conn, reader_lock) = connect_read_only(path)?;
        let schema: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if schema > STORAGE_SCHEMA {
            bail!(
                "database schema is newer than this binary (store schema {schema}, this binary {STORAGE_SCHEMA})"
            );
        }
        let tables: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('meta','objects','audit')",
            [],
            |r| r.get(0),
        )?;
        if tables != 3 {
            bail!("database is not an initialized keytend-kmip-server store");
        }
        let store = Self {
            conn,
            key,
            observed_history: Cell::new(None),
            history_failed: Cell::new(false),
            changes: RefCell::new(None),
            inserted: RefCell::new(None),
            cache: RefCell::new(super::cache::ObjectCache::new(super::CacheLimits::OFF)),
            index: RefCell::new(None),
            schema,
            _reader_lock: reader_lock,
        };
        let check: Vec<u8> = store
            .conn
            .query_row("SELECT value FROM meta WHERE name='key-check'", [], |r| {
                r.get(0)
            })
            .optional()?
            .context("master key check missing from the database")?;
        store.check_key(&check)?;
        let tip = store.with_state_read(|| {
            store.verify_audit()?;
            store.verify_objects()?;
            store.history_tip()
        })?;
        store.observe_history(tip);
        if store._reader_lock.is_some() && wal_frames(path)? {
            bail!(
                "{} changed while it was read without SQLite locking",
                path.display()
            );
        }
        Ok(store)
    }

    /// Fail unless `master_key` is a usable master-key file (exists, is
    /// readable, holds 32 bytes, is not accessible to other users).
    pub fn open_read_only_check_key_file(master_key: &Path) -> Result<()> {
        Self::read_master_key(master_key).map(drop)
    }

    /// Whether `master_key` is the key `path` is sealed under, from the
    /// key-check marker alone (no full verification). Errors other than a
    /// key mismatch (no database, unreadable key file, not a store) fail.
    pub fn master_key_opens(path: &Path, master_key: &Path) -> Result<bool> {
        let key = Self::read_master_key(master_key)?;
        if !fs::symlink_metadata(path)?.is_file() {
            bail!("database must be a regular file");
        }
        let (conn, _lock) = connect_read_only(path)?;
        let check: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE name='key-check'", [], |r| {
                r.get(0)
            })
            .optional()
            .context("database is not an initialized keytend-kmip-server store")?
            .context("master key check missing from the database")?;
        Ok(unseal_with(&key, KEY_CHECK_AAD, &check).is_ok_and(|p| p.as_slice() == KEY_CHECK))
    }

    /// Object records: for the current schema, the authenticated index bound
    /// to the audit head and every record it names; for an older store, every
    /// record's AEAD tag and identity (it has no index yet).
    pub(super) fn verify_objects(&self) -> Result<()> {
        if !self.legacy() {
            self.check_committed_state()?;
            return self.verify_object_state();
        }
        let existing: u32 = self.conn.query_row("SELECT (SELECT COUNT(*) FROM sqlite_schema WHERE name='object_state')+(SELECT COUNT(*) FROM meta WHERE name='object-state-root')", [], |row| row.get(0))?;
        if existing != 0 || self.audit_has_state()? {
            bail!("object state data exists under an older schema");
        }
        let mut statement = self
            .conn
            .prepare("SELECT id,owner,sealed FROM objects ORDER BY rowid")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let owner: String = row.get(1)?;
            let sealed: Vec<u8> = row.get(2)?;
            let plaintext = self.unseal(&Self::aad(&owner, &id), &sealed)?;
            Self::validate_record(&owner, &id, &plaintext)?;
        }
        Ok(())
    }

    /// `verify_integrity` in one read snapshot, with what it covered.
    pub fn verify(&self) -> Result<Verification> {
        let transaction = self
            .conn
            .is_autocommit()
            .then(|| self.conn.unchecked_transaction())
            .transpose()?;
        self.verify_integrity()?;
        let (objects, audit_entries): (i64, i64) = self.conn.query_row(
            "SELECT (SELECT COUNT(*) FROM objects),(SELECT COUNT(*) FROM audit)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if let Some(transaction) = transaction {
            let tip = self.history_tip()?;
            transaction.commit()?;
            self.observe_history(tip);
        }
        Ok(Verification {
            storage_schema: self.schema,
            objects: objects as u64,
            audit_entries: audit_entries as u64,
            object_index_verified: !self.legacy(),
        })
    }

    /// Check that this store (under the new key) is a master-key rotation of
    /// `source` (under the old key): its audit history repeats every event
    /// of `source` field for field, including the object-state roots, then
    /// the rotation event. With `exact`, nothing may follow the rotation
    /// event; otherwise later events are allowed. Both stores must already
    /// have been verified under their own keys.
    pub fn verify_rotation_of(&self, source: &Store, exact: bool) -> Result<()> {
        type Row = (i64, i64, String, u32, Option<String>, u32, Option<Vec<u8>>);
        const SQL: &str = "SELECT seq,timestamp,principal,operation,object_id,status,state_root FROM audit ORDER BY seq";
        let read = |row: &rusqlite::Row<'_>| -> rusqlite::Result<Row> {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        };
        if self.legacy() || source.legacy() {
            bail!("rotation check requires the current storage schema");
        }
        let mut before = source.conn.prepare(SQL)?;
        let mut after = self.conn.prepare(SQL)?;
        let mut before = before.query([])?;
        let mut after = after.query([])?;
        let mismatch = || {
            anyhow::anyhow!(
                "the store is not the master-key rotation of the pre-rotation copy (their audit histories differ)"
            )
        };
        while let Some(row) = before.next()? {
            let expected = read(row)?;
            let actual = after.next()?.ok_or_else(mismatch)?;
            if read(actual)? != expected {
                return Err(mismatch());
            }
        }
        let rotation = after.next()?.ok_or_else(mismatch)?;
        if read(rotation)?.2 != "keytend-kmip-server/storage-rotation" {
            return Err(mismatch());
        }
        if exact && after.next()?.is_some() {
            bail!(
                "the rotated copy and the pre-rotation copy differ: events were added after the rotation"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_paths_escape_query_and_fragment_characters() {
        assert_eq!(
            uri_path(Path::new("/data/a b?c#d%e.sqlite")).unwrap(),
            "/data/a%20b%3Fc%23d%25e.sqlite"
        );
    }
}
