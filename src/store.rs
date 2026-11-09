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

//! SQLite persistence: all object data is AEAD-encrypted; audit entries commit with mutations.
use crate::ttlv::Node;
use anyhow::{Context, Result, bail};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rand::rand_bytes,
    sign::Signer,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    cell::{Cell, RefCell},
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap, HashSet},
    fs,
    path::Path,
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};
mod cache;
mod census;
mod checkpoint;
mod history;
mod index;
mod lock;
mod read_only;
mod rotation;
mod state;
pub use census::{CensusPage, StoreSize};
pub use lock::WriterLock;
pub use read_only::Verification;
pub(crate) use read_only::{require_rollback_journal, sidecar};
pub use rotation::RotationSummary;
pub use state::STORAGE_SCHEMA;

#[derive(Clone, Serialize, Deserialize)]
pub struct WrappedValue {
    pub object: Node,
    pub version: [u32; 2],
    /// As Registered imports retain only ciphertext on disk, even after use.
    pub opaque: bool,
}
#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum MetadataOrigin {
    #[default]
    Legacy,
    Generated,
    Registered,
    Imported,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ObjectMetadata {
    #[serde(default)]
    pub version: [u32; 2],
    #[serde(default)]
    pub origin: MetadataOrigin,
    #[serde(default)]
    pub fresh: Option<bool>,
    #[serde(default)]
    pub always_sensitive: Option<bool>,
    #[serde(default)]
    pub never_extractable: Option<bool>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SplitSource {
    pub object_type: u32,
    pub secret_type: u32,
    #[serde(default = "default_opaque_type")]
    pub opaque_type: u32,
    #[serde(default = "default_pgp_version")]
    pub pgp_version: u32,
    #[serde(default = "default_certificate_type")]
    pub certificate_type: u32,
    #[serde(default)]
    pub pgp_signatures: Vec<u32>,
    pub format: u32,
    pub material_format: u32,
    pub length: usize,
    pub structured: bool,
    pub sensitive: bool,
    pub extractable: bool,
    pub split: Option<Box<SplitKeyMetadata>>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SplitKeyMetadata {
    pub parts: u32,
    pub part: u32,
    pub threshold: u32,
    pub method: u32,
    pub prime: Option<Vec<u8>>,
    /// Final editions use 285; draft GF sharing explicitly selects 283 or 285.
    pub polynomial: Option<u32>,
    #[serde(default)]
    pub source: Option<Box<SplitSource>>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub commitment: Option<Vec<u8>>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Object {
    pub id: String,
    pub owner: String,
    pub object_type: u32,
    #[serde(default = "default_secret_type")]
    pub secret_type: u32,
    #[serde(default = "default_opaque_type")]
    pub opaque_type: u32,
    #[serde(default = "default_pgp_version")]
    pub pgp_version: u32,
    #[serde(default = "default_certificate_type")]
    pub certificate_type: u32,
    pub format: u32,
    pub algorithm: u32,
    pub bits: u32,
    pub usage: u32,
    /// Server-selected protection storage; old records used this software backend.
    #[serde(default = "default_protection_mask")]
    pub protection_mask: u32,
    /// Lifetime budgets cannot be reset after protection or allocation, even
    /// when a successful allocation of zero leaves the remaining count unchanged.
    #[serde(default)]
    pub usage_consumed: bool,
    /// Server-owned history survives deletion or editing of client-visible links.
    #[serde(default)]
    pub replacement_id: Option<String>,
    #[serde(default)]
    pub wrapped: Option<WrappedValue>,
    #[serde(default)]
    pub imported: bool,
    #[serde(default)]
    pub metadata: ObjectMetadata,
    #[serde(default)]
    pub split: Option<SplitKeyMetadata>,
    pub state: u32,
    pub material: Vec<u8>,
    pub attrs: Vec<Node>,
    /// Stable per-identity instance numbers in the order of matching attrs.
    /// Missing entries in older records imply contiguous indices starting at 0.
    #[serde(default)]
    pub attribute_indices: BTreeMap<String, Vec<i32>>,
    pub created: i64,
    pub updated: i64,
}
fn default_protection_mask() -> u32 {
    1
}
fn default_pgp_version() -> u32 {
    4
}
fn default_opaque_type() -> u32 {
    0x80000000
}
fn default_secret_type() -> u32 {
    2
}
impl Drop for Object {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}
pub use cache::CacheLimits;
pub use index::{IndexKey, KeyFn};
pub struct Store {
    pub(crate) conn: Connection,
    key: Zeroizing<Vec<u8>>,
    observed_history: Cell<Option<history::HistoryTip>>,
    history_failed: Cell<bool>,
    /// Objects written while change recording is on, with their state before
    /// the first write. Used only to derive server-to-client messages.
    changes: RefCell<Option<Vec<Change>>>,
    /// Owner and identifier of each object inserted since `track_inserts`.
    inserted: RefCell<Option<Vec<(String, String)>>>,
    /// Storage schema of the open database. Read-write opens migrate, so this
    /// is below `STORAGE_SCHEMA` only for a read-only open of an older store.
    schema: i32,
    /// Decrypted objects (cache.rs); off unless `set_object_cache` turns it on.
    cache: RefCell<cache::ObjectCache>,
    /// Name and Link lookups (index.rs); off until `enable_index`.
    index: RefCell<Option<index::ObjectIndex>>,
    /// Shared writer lock held while an immutable read-only open reads the
    /// file (see `read_only.rs`); released on drop.
    _reader_lock: Option<fs::File>,
}
/// One object written during a recorded interval. `before` is None for an
/// insert. Rolled-back writes still appear; compare against current state.
pub struct Change {
    pub owner: String,
    pub id: String,
    pub before: Option<Object>,
}
pub const MAX_LOCATE_OFFSET: usize = 100_000;
const KEY_CHECK_AAD: &[u8] = b"keytend-kmip-server key check v1";
const KEY_CHECK: &[u8] = b"keytend-kmip-server v1";
fn unseal_with(key: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 29 || data[0] != 1 {
        bail!("invalid encrypted record");
    }
    Ok(Zeroizing::new(
        decrypt_aead(
            Cipher::aes_256_gcm(),
            key,
            Some(&data[1..13]),
            aad,
            &data[29..],
            &data[13..29],
        )
        .context("record authentication failed (wrong key or corrupted store)")?,
    ))
}
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
impl Store {
    pub(crate) fn read_master_key(master_key: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let key = Zeroizing::new(fs::read(master_key).context("read master key")?);
        if key.len() != 32 {
            bail!("master key must contain exactly 32 raw bytes");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(master_key)?.permissions().mode() & 0o007 != 0 {
                bail!("master key must not be accessible to other users");
            }
        }
        Ok(key)
    }
    pub fn open(path: &Path, master_key: &Path) -> Result<Self> {
        let key = Self::read_master_key(master_key)?;
        Self::open_with_key(path, key)
    }
    fn open_with_key(path: &Path, key: Zeroizing<Vec<u8>>) -> Result<Self> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        if !fs::symlink_metadata(path)?.is_file() {
            bail!("database must be a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(path)?.permissions().mode() & 0o007 != 0 {
                bail!("database must not be accessible to other users");
            }
        }
        let conn = Connection::open(path)?;
        let schema: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if schema > STORAGE_SCHEMA {
            bail!("database schema is newer than this binary");
        }
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;
            CREATE TABLE IF NOT EXISTS meta(name TEXT PRIMARY KEY,value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS objects(id TEXT PRIMARY KEY,owner TEXT NOT NULL, sealed BLOB NOT NULL);
            CREATE INDEX IF NOT EXISTS objects_owner ON objects(owner);
            CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, principal TEXT NOT NULL, operation INTEGER NOT NULL, object_id TEXT, status INTEGER NOT NULL, previous BLOB NOT NULL, mac BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS credential_replay(name BLOB PRIMARY KEY, value INTEGER NOT NULL);")?;
        let store = Self {
            conn,
            key,
            observed_history: Cell::new(None),
            history_failed: Cell::new(false),
            changes: RefCell::new(None),
            inserted: RefCell::new(None),
            cache: RefCell::new(cache::ObjectCache::new(CacheLimits::OFF)),
            index: RefCell::new(None),
            // Older stores are migrated below, before anything else reads them.
            schema: STORAGE_SCHEMA,
            _reader_lock: None,
        };
        let check: Option<Vec<u8>> = store
            .conn
            .query_row("SELECT value FROM meta WHERE name='key-check'", [], |r| {
                r.get(0)
            })
            .optional()?;
        // The domain strings here and in the audit, checkpoint, object-state
        // and credential-replay code are persisted format identifiers: stores,
        // audit chains and checkpoints are verified against them, so changing
        // one makes every existing store unreadable.
        if let Some(check) = check {
            store.check_key(&check)?;
        } else {
            let count: i64 = store.conn.query_row(
                "SELECT (SELECT COUNT(*) FROM objects)+(SELECT COUNT(*) FROM audit)",
                [],
                |r| r.get(0),
            )?;
            if count != 0 {
                bail!("master key check missing from an existing database");
            }
            let check = store.seal(KEY_CHECK_AAD, KEY_CHECK)?;
            store
                .conn
                .execute("INSERT INTO meta VALUES('key-check',?1)", [check])?;
        }
        if schema < STORAGE_SCHEMA {
            store.migrate_object_state()?;
        }
        let initial_tip = store.with_state_read(|| {
            store.verify_audit()?;
            store.check_committed_state()?;
            store.verify_object_state()?;
            store.history_tip()
        })?;
        store.observe_history(initial_tip);
        Ok(store)
    }
    /// Fails unless `check` (the stored key-check marker) was sealed with this
    /// store's key.
    fn check_key(&self, check: &[u8]) -> Result<()> {
        if self.unseal(KEY_CHECK_AAD, check)?.as_slice() != KEY_CHECK {
            bail!("invalid master key");
        }
        Ok(())
    }
    /// Storage schema of the open database (`PRAGMA user_version`).
    pub fn storage_schema(&self) -> i32 {
        self.schema
    }
    /// A read-only open of a store older than `STORAGE_SCHEMA`: it has no
    /// authenticated object index yet, and the server builds one when it
    /// first opens the store.
    pub(crate) fn legacy(&self) -> bool {
        self.schema < STORAGE_SCHEMA
    }
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0; 12];
        rand_bytes(&mut nonce)?;
        let mut tag = [0; 16];
        let ct = encrypt_aead(
            Cipher::aes_256_gcm(),
            &self.key,
            Some(&nonce),
            aad,
            plaintext,
            &mut tag,
        )?;
        let mut out = vec![1];
        out.extend(nonce);
        out.extend(tag);
        out.extend(ct);
        Ok(out)
    }
    fn unseal(&self, aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        unseal_with(&self.key, aad, data)
    }
    fn aad(owner: &str, id: &str) -> Vec<u8> {
        format!("keytend-kmip-server object v1\0{owner}\0{id}").into_bytes()
    }
    /// Turn the decrypted-object cache on (a nonzero size) or off.
    pub fn set_object_cache(&self, limits: CacheLimits) {
        self.cache.borrow_mut().set_limits(limits);
    }
    /// Drop cached objects unused for longer than the cache's idle time.
    pub fn expire_object_cache(&self) {
        self.cache.borrow_mut().expire(std::time::Instant::now());
    }
    /// Build the object index from every record. On failure the index stays
    /// off and lookups scan, as without it.
    pub fn enable_index(&self, keys_fn: KeyFn) -> Result<()> {
        let mut built = index::ObjectIndex::new(keys_fn);
        self.with_state_read(|| {
            self.walk_state(|id, owner, rowid, hash| {
                built.set(id, Some(&self.decode_walked(id, owner, rowid, hash)?.0));
                Ok(false)
            })
        })?;
        *self.index.borrow_mut() = Some(built);
        Ok(())
    }
    /// Identifiers that may hold `key`, or None without an index.
    pub fn index_candidates(&self, key: &IndexKey) -> Option<Vec<String>> {
        self.index.borrow().as_ref().map(|ix| ix.candidates(key))
    }
    /// Prune the identifiers written since the last clean point to their
    /// committed keys. Only outside a transaction, so a later rollback cannot
    /// bring back a version whose keys were dropped. A failure turns the
    /// index off.
    fn prune_index(&self) {
        if !self.conn.is_autocommit() {
            return;
        }
        let Some(dirty) = self.index.borrow_mut().as_mut().map(|ix| ix.take_dirty()) else {
            return;
        };
        if dirty.is_empty() {
            return;
        }
        let result = self.with_state_read(|| {
            let mut current = Vec::with_capacity(dirty.len());
            for id in &dirty {
                let object = match self.find_record(id)? {
                    Some((owner, rowid, hash)) => Some(self.walked(id, &owner, rowid, &hash)?),
                    None => None,
                };
                current.push((id, object));
            }
            Ok(current)
        });
        let mut slot = self.index.borrow_mut();
        match (result, slot.as_mut()) {
            (Ok(current), Some(ix)) => {
                for (id, object) in current {
                    ix.set(id, object.as_deref());
                }
            }
            (Err(error), _) => {
                tracing::warn!(error = %error, "object index turned off; lookups scan");
                *slot = None;
            }
            _ => {}
        }
    }
    /// Decrypt and parse the record of an authenticated index node, with its
    /// decrypted length.
    fn decode_walked(
        &self,
        id: &str,
        owner: &str,
        rowid: i64,
        value_hash: &[u8; 32],
    ) -> Result<(Object, usize)> {
        let data = self.walked_record(id, owner, rowid, value_hash)?;
        let plaintext = self.unseal(&Self::aad(owner, id), &data)?;
        Self::validate_record(owner, id, &plaintext)?;
        Ok((
            serde_json::from_slice::<Object>(&plaintext)?,
            plaintext.len(),
        ))
    }
    /// The object of an authenticated index node: from the cache when the
    /// record's hash still matches, otherwise read, decrypted and cached.
    /// Inside `walk_state` the node is already authenticated, so neither the
    /// history check nor a second index descent is repeated per object.
    fn walked(
        &self,
        id: &str,
        owner: &str,
        rowid: i64,
        value_hash: &[u8; 32],
    ) -> Result<Arc<Object>> {
        if let Some(object) = self.cache.borrow_mut().get(owner, id, value_hash) {
            return Ok(object);
        }
        let (object, size) = self.decode_walked(id, owner, rowid, value_hash)?;
        let object = Arc::new(object);
        self.cache
            .borrow_mut()
            .insert(owner, id, value_hash, object.clone(), size);
        Ok(object)
    }
    pub fn get(&self, owner: &str, id: &str) -> Result<Option<Object>> {
        self.with_state_read(|| {
            let Some((node_owner, rowid, hash)) = self.find_record(id)? else {
                return Ok(None);
            };
            if node_owner != owner {
                return Ok(None);
            }
            Ok(Some(Object::clone(&*self.walked(id, owner, rowid, &hash)?)))
        })
    }
    fn serialize_object(obj: &Object) -> Result<Zeroizing<Vec<u8>>> {
        if obj.wrapped.as_ref().is_some_and(|value| value.opaque) {
            let mut stored = obj.clone();
            stored.material.zeroize();
            stored.material.clear();
            Ok(Zeroizing::new(serde_json::to_vec(&stored)?))
        } else {
            Ok(Zeroizing::new(serde_json::to_vec(obj)?))
        }
    }
    pub fn owner_of(&self, id: &str) -> Result<Option<String>> {
        self.with_state_read(|| self.authenticated_owner(id))
    }
    /// Start recording written objects; replaces any previous recording.
    pub fn record_changes(&self) {
        *self.changes.borrow_mut() = Some(vec![]);
    }
    /// Stop recording and return the objects written since it started.
    pub fn take_changes(&self) -> Vec<Change> {
        self.changes.borrow_mut().take().unwrap_or_default()
    }
    /// Start listing inserted objects; replaces any previous list.
    pub fn track_inserts(&self) {
        *self.inserted.borrow_mut() = Some(vec![]);
    }
    /// Stop listing and return the (owner, identifier) of each insert since
    /// `track_inserts`. Rolled-back inserts still appear.
    pub fn take_inserts(&self) -> Vec<(String, String)> {
        self.inserted.borrow_mut().take().unwrap_or_default()
    }
    fn note_change(&self, obj: &Object, inserted: bool) -> Result<()> {
        let recorded = match self.changes.borrow().as_ref() {
            None => return Ok(()),
            Some(changes) => changes
                .iter()
                .any(|c| c.id == obj.id && c.owner == obj.owner),
        };
        if recorded {
            return Ok(());
        }
        let before = if inserted {
            None
        } else {
            self.get(&obj.owner, &obj.id)?
        };
        if let Some(changes) = self.changes.borrow_mut().as_mut() {
            changes.push(Change {
                owner: obj.owner.clone(),
                id: obj.id.clone(),
                before,
            });
        }
        Ok(())
    }
    pub fn insert(&self, obj: &Object) -> Result<()> {
        self.note_change(obj, true)?;
        self.cache.borrow_mut().remove(&obj.id);
        if let Some(inserted) = self.inserted.borrow_mut().as_mut() {
            inserted.push((obj.owner.clone(), obj.id.clone()));
        }
        self.mutate_state(|| {
            if self.authenticated_owner(&obj.id)?.is_some() {
                bail!("object identifier already exists");
            }
            let plaintext = Self::serialize_object(obj)?;
            let sealed = self.seal(&Self::aad(&obj.owner, &obj.id), &plaintext)?;
            self.conn.execute(
                "INSERT INTO objects(id,owner,sealed) VALUES(?1,?2,?3)",
                params![obj.id, obj.owner, sealed],
            )?;
            self.index_object_record(&obj.id, &obj.owner, self.conn.last_insert_rowid(), &sealed)
        })?;
        if let Some(ix) = self.index.borrow_mut().as_mut() {
            ix.add(obj);
        }
        self.prune_index();
        Ok(())
    }
    pub fn put(&self, obj: &Object) -> Result<()> {
        self.note_change(obj, false)?;
        // The new record's hash would miss anyway; free the memory now.
        self.cache.borrow_mut().remove(&obj.id);
        self.mutate_state(|| {
            self.authenticated_record(&obj.owner, &obj.id)?
                .context("cannot update a missing object or a different owner's object")?;
            let plaintext = Self::serialize_object(obj)?;
            let sealed = self.seal(&Self::aad(&obj.owner, &obj.id), &plaintext)?;
            let rowid: i64 = self.conn.query_row(
                "SELECT rowid FROM objects WHERE id=?1 AND owner=?2",
                params![obj.id, obj.owner],
                |row| row.get(0),
            )?;
            let changed = self.conn.execute(
                "UPDATE objects SET sealed=?3 WHERE id=?1 AND owner=?2",
                params![obj.id, obj.owner, sealed],
            )?;
            if changed != 1 {
                bail!("cannot update a missing object or a different owner's object");
            }
            self.index_object_record(&obj.id, &obj.owner, rowid, &sealed)
        })?;
        if let Some(ix) = self.index.borrow_mut().as_mut() {
            ix.add(obj);
        }
        self.prune_index();
        Ok(())
    }
    /// Delete an object record and all of its stored metadata (draft 3.0
    /// Obliterate). Audit events that name the identifier are retained.
    pub fn remove(&self, owner: &str, id: &str) -> Result<()> {
        self.cache.borrow_mut().remove(id);
        self.mutate_state(|| self.remove_object_record(owner, id))?;
        if let Some(ix) = self.index.borrow_mut().as_mut() {
            ix.touch(id);
        }
        self.prune_index();
        Ok(())
    }
    pub fn list(&self, owner: &str) -> Result<Vec<Object>> {
        self.with_state_read(|| {
            let mut objects = Vec::new();
            self.walk_state(|id, object_owner, rowid, hash| {
                if object_owner == owner {
                    objects.push(Object::clone(&*self.walked(id, owner, rowid, hash)?));
                }
                Ok(false)
            })?;
            Ok(objects)
        })
    }
    /// Scan authenticated inventory without decrypting unselected records.
    pub fn any_object(&self, predicate: impl Fn(&Object) -> bool) -> Result<bool> {
        self.with_state_read(|| {
            let mut found = false;
            self.walk_state(|id, owner, rowid, hash| {
                let object = self.walked(id, owner, rowid, hash)?;
                found = predicate(&object);
                Ok(found)
            })?;
            Ok(found)
        })
    }
    /// Order by encrypted creation time without exposing metadata in an SQL index.
    /// Keep at most offset + max IDs, with hard bounds on both request fields.
    pub fn locate(
        &self,
        owner: &str,
        offset: usize,
        max: usize,
        filter: impl Fn(&Object) -> bool,
    ) -> Result<(usize, Vec<String>)> {
        self.locate_scoped(owner, &[], offset, max, filter)
    }
    /// Include only exact additional owner/identifier pairs before decryption or pagination.
    pub fn locate_scoped(
        &self,
        owner: &str,
        grants: &[(String, &str)],
        offset: usize,
        max: usize,
        filter: impl Fn(&Object) -> bool,
    ) -> Result<(usize, Vec<String>)> {
        self.locate_ordered(owner, grants, offset, max, false, filter)
    }
    /// As `locate_scoped`, newest first or, with `oldest_first`, in creation order.
    pub fn locate_ordered(
        &self,
        owner: &str,
        grants: &[(String, &str)],
        offset: usize,
        max: usize,
        oldest_first: bool,
        filter: impl Fn(&Object) -> bool,
    ) -> Result<(usize, Vec<String>)> {
        self.locate_among(owner, grants, None, offset, max, oldest_first, filter)
    }
    /// As `locate_ordered`, examining only `candidates` (from the object
    /// index) when given; the filter still decides every result, so the
    /// answer is the same as a full scan's whenever the candidates include
    /// every match.
    #[allow(clippy::too_many_arguments)]
    pub fn locate_among(
        &self,
        owner: &str,
        grants: &[(String, &str)],
        candidates: Option<&[String]>,
        offset: usize,
        max: usize,
        oldest_first: bool,
        filter: impl Fn(&Object) -> bool,
    ) -> Result<(usize, Vec<String>)> {
        self.with_state_read(|| {
            if offset > MAX_LOCATE_OFFSET || max > 1000 || grants.len() > 256 {
                bail!("Locate pagination or grant count exceeds resource limits");
            }
            let keep = offset + max;
            let grants = grants
                .iter()
                .map(|(owner, id)| (owner.as_str(), *id))
                .collect::<HashSet<_>>();
            let mut total = 0;
            let mut selected = BinaryHeap::new();
            let mut visit = |id: &str, object_owner: &str, rowid: i64, hash: &[u8; 32]| {
                if object_owner != owner && !grants.contains(&(object_owner, id)) {
                    return Ok(false);
                }
                let object = self.walked(id, object_owner, rowid, hash)?;
                if filter(&object) {
                    if keep > 0 {
                        // The heap's top is the kept key that sorts last.
                        let key = (object.created, rowid, id.to_owned());
                        let key = if oldest_first {
                            Ok(key)
                        } else {
                            Err(Reverse(key))
                        };
                        if selected.len() < keep {
                            selected.push(key);
                        } else if selected.peek().is_some_and(|last| key < *last) {
                            selected.pop();
                            selected.push(key);
                        }
                    }
                    total += 1;
                }
                Ok(false)
            };
            match candidates {
                None => self.walk_state(visit)?,
                Some(ids) => {
                    for id in ids {
                        if let Some((object_owner, rowid, hash)) = self.find_record(id)? {
                            visit(id, &object_owner, rowid, &hash)?;
                        }
                    }
                }
            }
            Ok((
                total,
                selected
                    .into_sorted_vec()
                    .into_iter()
                    .map(|(Ok(key) | Err(Reverse(key)))| key)
                    .skip(offset)
                    .take(max)
                    .map(|(_, _, id)| id)
                    .collect(),
            ))
        })
    }
    pub fn begin(&self) -> Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        if let Err(error) = self
            .check_live_history()
            .and_then(|()| self.check_committed_state())
        {
            self.conn.execute_batch("ROLLBACK")?;
            return Err(error);
        }
        Ok(())
    }
    pub fn commit(&self) -> Result<()> {
        if self.conn.is_autocommit() {
            bail!("no storage transaction to commit");
        }
        self.check_live_history()?;
        if !self.committed_state_matches()? {
            self.audit("keytend-kmip-server/storage", 0, None, 0)?;
        }
        self.check_committed_state()?;
        let tip = self.history_tip()?;
        self.conn.execute_batch("COMMIT")?;
        self.observe_history(tip);
        self.prune_index();
        Ok(())
    }
    pub fn rollback(&self) -> Result<()> {
        self.conn.execute_batch("ROLLBACK")?;
        self.prune_index();
        Ok(())
    }
    pub fn audit(&self, owner: &str, op: u32, id: Option<&str>, status: u32) -> Result<()> {
        let transaction = self
            .conn
            .is_autocommit()
            .then(|| {
                rusqlite::Transaction::new_unchecked(
                    &self.conn,
                    rusqlite::TransactionBehavior::Immediate,
                )
            })
            .transpose()?;
        if transaction.is_some() {
            self.check_live_history()?;
            self.check_committed_state()?;
        }
        let prev: Vec<u8> = self
            .conn
            .query_row("SELECT mac FROM audit ORDER BY seq DESC LIMIT 1", [], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(vec![0; 32]);
        let seq: i64 =
            self.conn
                .query_row("SELECT COALESCE(MAX(seq),0)+1 FROM audit", [], |r| r.get(0))?;
        let time = now();
        let state = self.state_commitment()?;
        let mac = self.audit_mac(seq, time, owner, op, id, status, &prev, Some(&state))?;
        self.conn.execute(
            "INSERT INTO audit VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![seq, time, owner, op, id, status, prev, mac, state],
        )?;
        if let Some(transaction) = transaction {
            let tip = self.history_tip()?;
            transaction.commit()?;
            self.observe_history(tip);
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn audit_mac(
        &self,
        seq: i64,
        time: i64,
        owner: &str,
        op: u32,
        id: Option<&str>,
        status: u32,
        prev: &[u8],
        state: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key = PKey::hmac(&self.key)?;
        let mut s = Signer::new(MessageDigest::sha256(), &key)?;
        let fields = (seq, time, owner, op, id, status, hex::encode(prev));
        if let Some(root) = state {
            if root.len() != 32 {
                bail!("invalid audit object state root");
            }
            s.update(b"keytend-kmip-server audit v2\0")?;
            s.update(&serde_json::to_vec(&(fields, hex::encode(root)))?)?;
        } else {
            s.update(b"keytend-kmip-server audit v1\0")?;
            s.update(&serde_json::to_vec(&fields)?)?;
        }
        Ok(s.sign_to_vec()?)
    }
    pub fn verify_audit(&self) -> Result<()> {
        use subtle::ConstantTimeEq;
        let transaction = self
            .conn
            .is_autocommit()
            .then(|| self.conn.unchecked_transaction())
            .transpose()?;
        self.check_live_history()?;
        let sql = if self.audit_has_state()? {
            "SELECT seq,timestamp,principal,operation,object_id,status,previous,mac,state_root FROM audit ORDER BY seq"
        } else {
            "SELECT seq,timestamp,principal,operation,object_id,status,previous,mac,NULL FROM audit ORDER BY seq"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query([])?;
        let mut expected = vec![0; 32];
        let mut n = 0;
        while let Some(r) = rows.next()? {
            let seq: i64 = r.get(0)?;
            let time = r.get(1)?;
            let owner: String = r.get(2)?;
            let op = r.get(3)?;
            let id: Option<String> = r.get(4)?;
            let status = r.get(5)?;
            let prev: Vec<u8> = r.get(6)?;
            let mac: Vec<u8> = r.get(7)?;
            let state: Option<Vec<u8>> = r.get(8)?;
            n += 1;
            if seq != n
                || !bool::from(prev.ct_eq(&expected))
                || !bool::from(mac.ct_eq(&self.audit_mac(
                    seq,
                    time,
                    &owner,
                    op,
                    id.as_deref(),
                    status,
                    &prev,
                    state.as_deref(),
                )?))
            {
                bail!("audit integrity failure");
            }
            expected = mac;
        }
        if let Some(transaction) = transaction {
            let tip = self.history_tip()?;
            transaction.commit()?;
            self.observe_history(tip);
        }
        Ok(())
    }
    /// Consistent encrypted SQLite snapshot, including the audit chain. Refuses
    /// overwrite. The source is only read, and an older store is copied as it
    /// is, without migration; the copy is verified read-only before it is
    /// published, so verification does not migrate it either.
    pub fn backup(&self, output: &Path) -> Result<Verification> {
        let floor = self.with_state_read(|| self.history_tip())?;
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut name = output.as_os_str().to_os_string();
            name.push(suffix);
            match fs::symlink_metadata(Path::new(&name)) {
                Ok(_) => bail!(
                    "backup output or SQLite sidecar {} already exists",
                    Path::new(&name).display()
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let staging = tempfile::Builder::new()
            .prefix(".keytend-kmip-server-backup-")
            .tempdir_in(parent)?;
        let staged_path = staging.path().join("kmip.sqlite");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let f = options.open(&staged_path)?;
        // VACUUM INTO runs on a read-only connection and writes a standalone
        // rollback-journal database: the copy needs no -wal or -shm file.
        self.conn.execute(
            "VACUUM main INTO ?1",
            [staged_path.to_str().context("backup path must be UTF-8")?],
        )?;
        read_only::require_rollback_journal(&staged_path)?;
        // Authenticate the actual copied snapshot, including its complete index,
        // before publishing it. A pre-copy check alone would permit a race.
        let snapshot =
            Self::open_read_only_with_key(&staged_path, Zeroizing::new(self.key.to_vec()))?;
        let verification = snapshot.verify()?;
        snapshot.with_state_read(|| snapshot.verify_history_floor(floor))?;
        drop(snapshot);
        f.sync_all()?;
        fs::hard_link(&staged_path, output)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(verification)
    }
    /// Raise one replay counter (KMIP 2.0+ Hashed Password timestamps and
    /// One Time Password time steps). Returns true, and stores `value`, only
    /// when it exceeds the stored value. Counters are keyed by an opaque
    /// digest, so the table names no user. The write commits on its own: a
    /// later rollback must never return a used value, so it is refused
    /// inside a transaction.
    pub fn advance_replay_counter(&self, name: &[u8; 32], value: i64) -> Result<bool> {
        if !self.conn.is_autocommit() {
            bail!("replay counters are not written inside a transaction");
        }
        let changed = self.conn.execute(
            "INSERT INTO credential_replay(name,value) VALUES(?1,?2) ON CONFLICT(name) DO UPDATE SET value=excluded.value WHERE excluded.value > credential_replay.value",
            params![&name[..], value],
        )?;
        Ok(changed == 1)
    }
    pub fn healthy(&self) -> bool {
        self.with_state_read(|| Ok(())).is_ok()
    }
}

fn default_certificate_type() -> u32 {
    1
}
