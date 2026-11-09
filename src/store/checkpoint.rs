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

//! An authenticated audit floor requires independent retention. It is not a
//! signature, remote witness, or object-state root.
use super::*;
use std::io::{Read, Write};
use subtle::ConstantTimeEq;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    store_id: String,
    sequence: i64,
    head_mac: String,
    authentication: String,
}

impl Store {
    fn checkpoint_store_id(&self) -> Result<String> {
        let marker: Vec<u8> =
            self.conn
                .query_row("SELECT value FROM meta WHERE name='key-check'", [], |row| {
                    row.get(0)
                })?;
        Ok(hex::encode(openssl::hash::hash(
            MessageDigest::sha256(),
            &marker,
        )?))
    }

    fn checkpoint_mac(&self, checkpoint: &Checkpoint) -> Result<Vec<u8>> {
        let key = PKey::hmac(&self.key)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(b"keytend-kmip-server external audit checkpoint v1\0")?;
        signer.update(&serde_json::to_vec(&(
            checkpoint.version,
            &checkpoint.store_id,
            checkpoint.sequence,
            &checkpoint.head_mac,
        ))?)?;
        Ok(signer.sign_to_vec()?)
    }

    /// Verify authentication, store identity, complete current chain, and the
    /// retained prefix. Later audit entries are allowed. A missing floor fails
    /// closed; the caller must choose a separately protected checkpoint path.
    pub fn verify_audit_checkpoint(&self, path: &Path) -> Result<()> {
        let file = fs::File::open(path).context("read required external audit checkpoint")?;
        if !file.metadata()?.is_file() {
            bail!("audit checkpoint must be a regular file");
        }
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            bail!("audit checkpoint exceeds size limit");
        }
        let checkpoint: Checkpoint =
            serde_json::from_slice(&bytes).context("invalid audit checkpoint")?;
        if checkpoint.version != 1
            || checkpoint.sequence < 0
            || checkpoint.store_id.len() != 64
            || checkpoint.head_mac.len() != 64
            || checkpoint.authentication.len() != 64
        {
            bail!("invalid audit checkpoint fields");
        }
        let mac =
            hex::decode(&checkpoint.authentication).context("invalid checkpoint authentication")?;
        if !bool::from(mac.ct_eq(&self.checkpoint_mac(&checkpoint)?)) {
            bail!("audit checkpoint authentication failed");
        }
        let transaction = self
            .conn
            .is_autocommit()
            .then(|| self.conn.unchecked_transaction())
            .transpose()?;
        if checkpoint.store_id != self.checkpoint_store_id()? {
            bail!("audit checkpoint belongs to another store or storage-key generation");
        }
        self.verify_audit()?;
        self.verify_objects()?;
        let expected = hex::decode(&checkpoint.head_mac).context("invalid checkpoint head")?;
        let retained: Option<Vec<u8>> = if checkpoint.sequence == 0 {
            Some(vec![0; 32])
        } else {
            self.conn
                .query_row(
                    "SELECT mac FROM audit WHERE seq=?1",
                    [checkpoint.sequence],
                    |row| row.get(0),
                )
                .optional()?
        };
        if !retained
            .as_ref()
            .is_some_and(|value| bool::from(value.ct_eq(&expected)))
        {
            bail!("audit history is older than or diverges from the required checkpoint");
        }
        if let Some(transaction) = transaction {
            let tip = self.history_tip()?;
            transaction.commit()?;
            self.observe_history(tip);
        }
        Ok(())
    }

    /// Export an immutable checkpoint from one validated read snapshot. Requiring
    /// the previous independently retained checkpoint prevents accidental export
    /// of a lower or divergent floor. Publication never overwrites a prior file.
    pub fn write_audit_checkpoint(&self, output: &Path, previous: Option<&Path>) -> Result<()> {
        let transaction = self.conn.unchecked_transaction()?;
        self.verify_integrity()?;
        if let Some(previous) = previous {
            self.verify_audit_checkpoint(previous)?;
        }
        let (sequence, head): (i64, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, vec![0; 32]));
        let mut checkpoint = Checkpoint {
            version: 1,
            store_id: self.checkpoint_store_id()?,
            sequence,
            head_mac: hex::encode(head),
            authentication: String::new(),
        };
        checkpoint.authentication = hex::encode(self.checkpoint_mac(&checkpoint)?);
        let mut bytes = serde_json::to_vec_pretty(&checkpoint)?;
        bytes.push(b'\n');
        let tip = self.history_tip()?;
        transaction.commit()?;
        self.observe_history(tip);
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(output).map_err(|e| {
            if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow::anyhow!(
                    "audit checkpoint output {} already exists",
                    output.display()
                )
            } else {
                anyhow::Error::new(e.error).context("publish immutable audit checkpoint")
            }
        })?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}
