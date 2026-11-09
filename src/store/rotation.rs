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

//! Build a fresh encrypted snapshot; never switch a live connection's key.
use super::*;
use subtle::ConstantTimeEq;

#[derive(Debug, PartialEq, Eq)]
pub struct RotationSummary {
    pub objects: u64,
    pub audit_entries: u64,
}

impl Store {
    pub(super) fn validate_record(owner: &str, id: &str, plaintext: &[u8]) -> Result<()> {
        let object: Object = serde_json::from_slice(plaintext)?;
        if object.owner != owner || object.id != id {
            bail!("encrypted object identity does not match its storage identity");
        }
        Ok(())
    }

    /// Offline integrity check of SQLite, the audit chain, and every encrypted object.
    pub fn verify_integrity(&self) -> Result<()> {
        let transaction = self
            .conn
            .is_autocommit()
            .then(|| self.conn.unchecked_transaction())
            .transpose()?;
        self.check_live_history()?;
        let check: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if check != "ok" {
            bail!("SQLite integrity check failed");
        }
        self.verify_audit()?;
        self.verify_objects()?;
        if let Some(transaction) = transaction {
            let tip = self.history_tip()?;
            transaction.commit()?;
            self.observe_history(tip);
        }
        Ok(())
    }

    /// Publish a consistent snapshot with fresh AEAD records and a reauthenticated
    /// audit chain. The source remains usable with its original key. No plaintext
    /// records or old-key ciphertext are written to the new database.
    pub fn rotate_master_key(
        &self,
        new_master_key: &Path,
        output: &Path,
    ) -> Result<RotationSummary> {
        self.rotate_master_key_checked(new_master_key, output, None)
    }

    /// Require an independently retained audit floor within the source snapshot.
    pub fn rotate_master_key_checked(
        &self,
        new_master_key: &Path,
        output: &Path,
        checkpoint: Option<&Path>,
    ) -> Result<RotationSummary> {
        let key = Self::read_master_key(new_master_key)?;
        if bool::from(key.ct_eq(&self.key)) {
            bail!("new master key must differ from the current master key");
        }
        // Refuse existing names, including dangling symlinks and stale SQLite
        // sidecars. Publishing later uses an atomic, no-overwrite hard link.
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut name = output.as_os_str().to_os_string();
            name.push(suffix);
            match fs::symlink_metadata(Path::new(&name)) {
                Ok(_) => bail!(
                    "rotation output or SQLite sidecar {} already exists",
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
        // TempDir is private and on the destination filesystem. Unsuccessful
        // operations clean up staging; interruption can leave only encrypted
        // staging data, never a success-looking output path.
        let staging = tempfile::Builder::new()
            .prefix(".keytend-kmip-server-rotate-")
            .tempdir_in(parent)?;
        let staged_path = staging.path().join("kmip.sqlite");
        // Use validated in-memory bytes; never copy key files into staging.
        let target = Self::open_with_key(&staged_path, key)?;
        // A deferred read transaction pins one WAL snapshot for both histories
        // and objects, even if a writer commits while this copy is running.
        let source_transaction = self.conn.unchecked_transaction()?;
        let schema: i32 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if schema != STORAGE_SCHEMA {
            bail!("rotation requires the current storage schema");
        }
        self.verify_integrity()?;
        if let Some(checkpoint) = checkpoint {
            self.verify_audit_checkpoint(checkpoint)?;
        }
        let unknown_meta: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM meta WHERE name NOT IN ('key-check','object-state-root')",
            [],
            |r| r.get(0),
        )?;
        if unknown_meta != 0 {
            bail!("rotation cannot preserve unknown storage metadata");
        }
        let target_transaction = target.conn.unchecked_transaction()?;
        let mut summary = RotationSummary {
            objects: 0,
            audit_entries: 0,
        };
        {
            let mut stmt = self
                .conn
                .prepare("SELECT id,owner,sealed,rowid FROM objects ORDER BY rowid")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let owner: String = row.get(1)?;
                let data: Vec<u8> = row.get(2)?;
                let aad = Self::aad(&owner, &id);
                let plaintext = self.unseal(&aad, &data)?;
                // Preserve the complete serialized record, including fields
                // this writer does not interpret, without resetting history.
                target_transaction.execute(
                    "INSERT INTO objects(id,owner,sealed,rowid) VALUES(?1,?2,?3,?4)",
                    params![
                        id,
                        owner,
                        target.seal(&aad, &plaintext)?,
                        row.get::<_, i64>(3)?
                    ],
                )?;
                summary.objects += 1;
            }
        }
        target.build_object_state()?;
        // Replay counters carry over, so a rotation never re-admits a used
        // One Time Password or Hashed Password timestamp.
        {
            let mut stmt = self
                .conn
                .prepare("SELECT name,value FROM credential_replay")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                target_transaction.execute(
                    "INSERT INTO credential_replay(name,value) VALUES(?1,?2)",
                    params![row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?],
                )?;
            }
        }
        {
            let mut stmt = self.conn.prepare(
                "SELECT seq,timestamp,principal,operation,object_id,status,state_root FROM audit ORDER BY seq",
            )?;
            let mut rows = stmt.query([])?;
            let mut previous = vec![0; 32];
            while let Some(row) = rows.next()? {
                let seq: i64 = row.get(0)?;
                let timestamp: i64 = row.get(1)?;
                let principal: String = row.get(2)?;
                let operation: u32 = row.get(3)?;
                let object_id: Option<String> = row.get(4)?;
                let status: u32 = row.get(5)?;
                let state: Option<Vec<u8>> = row.get(6)?;
                let mac = target.audit_mac(
                    seq,
                    timestamp,
                    &principal,
                    operation,
                    object_id.as_deref(),
                    status,
                    &previous,
                    state.as_deref(),
                )?;
                target_transaction.execute(
                    "INSERT INTO audit VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    params![
                        seq, timestamp, principal, operation, object_id, status, previous, mac,
                        state
                    ],
                )?;
                previous = mac;
                summary.audit_entries += 1;
            }
        }
        target.audit("keytend-kmip-server/storage-rotation", 0, None, 0)?;
        summary.audit_entries += 1;
        target.verify_integrity()?;
        let target_tip = target.history_tip()?;
        target_transaction.commit()?;
        target.observe_history(target_tip);
        let source_tip = self.history_tip()?;
        source_transaction.commit()?;
        self.observe_history(source_tip);
        // Publish a standalone file with no WAL dependency, after verification
        // and durable writes. No key changes take place in the source store.
        target
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")?;
        drop(target);
        fs::File::open(&staged_path)?.sync_all()?;
        fs::hard_link(&staged_path, output)
            .context("publish rotated snapshot without overwriting")?;
        // A sync failure after publication is reported as failure: operators
        // must verify the candidate and storage durability before cutover.
        fs::File::open(parent)?.sync_all()?;
        Ok(summary)
    }
}
