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

//! Authenticated AVL index of encrypted object records. Roots are committed by
//! audit v2 MACs; SQLite savepoints roll back records, nodes and roots together.
use super::*;
use subtle::ConstantTimeEq;

pub const STORAGE_SCHEMA: i32 = 18;
const ROOT_NAME: &str = "object-state-root";
const ROOT_AAD: &[u8] = b"keytend-kmip-server object state root v1";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reference {
    id: Option<String>,
    hash: [u8; 32],
    height: u32,
    count: u64,
}
impl Reference {
    fn empty() -> Self {
        Self {
            id: None,
            hash: [0; 32],
            height: 0,
            count: 0,
        }
    }
    fn valid(&self) -> bool {
        if self.id.is_none() {
            *self == Self::empty()
        } else {
            (1..=64).contains(&self.height) && self.count > 0
        }
    }
    fn commitment(&self) -> Result<Vec<u8>> {
        let mut input = b"keytend-kmip-server object state commitment v1\0".to_vec();
        input.extend(serde_json::to_vec(self)?);
        Ok(crate::crypto::sha256(&input).to_vec())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexNode {
    id: String,
    owner: String,
    rowid: i64,
    value_hash: [u8; 32],
    left: Reference,
    right: Reference,
}
impl IndexNode {
    fn reference(&self) -> Result<Reference> {
        if self.rowid <= 0
            || !self.left.valid()
            || !self.right.valid()
            || self.left.height.max(self.right.height) >= 64
            || self.left.height.abs_diff(self.right.height) > 1
            || self.left.id.as_ref().is_some_and(|id| id >= &self.id)
            || self.right.id.as_ref().is_some_and(|id| id <= &self.id)
        {
            bail!("invalid object state index node");
        }
        let mut input = b"keytend-kmip-server object state node v1\0".to_vec();
        input.extend(serde_json::to_vec(self)?);
        Ok(Reference {
            id: Some(self.id.clone()),
            hash: crate::crypto::sha256(&input),
            height: 1 + self.left.height.max(self.right.height),
            count: self
                .left
                .count
                .checked_add(self.right.count)
                .and_then(|count| count.checked_add(1))
                .context("object state count overflow")?,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateRoot {
    version: u32,
    root: Reference,
}
struct StandaloneRollback<'a>(&'a Connection);
impl Drop for StandaloneRollback<'_> {
    fn drop(&mut self) {
        if !self.0.is_autocommit() {
            let _ = self.0.execute_batch("ROLLBACK");
        }
    }
}

impl Store {
    fn state_root(&self) -> Result<Reference> {
        let sealed: Vec<u8> =
            self.conn
                .query_row("SELECT value FROM meta WHERE name=?1", [ROOT_NAME], |row| {
                    row.get(0)
                })?;
        let bytes = self.unseal(ROOT_AAD, &sealed)?;
        let state: StateRoot = serde_json::from_slice(&bytes)?;
        if state.version != 1 || !state.root.valid() {
            bail!("invalid object state root");
        }
        Ok(state.root)
    }
    fn set_state_root(&self, root: Reference) -> Result<()> {
        let bytes = serde_json::to_vec(&StateRoot { version: 1, root })?;
        self.conn.execute("INSERT INTO meta(name,value) VALUES(?1,?2) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            params![ROOT_NAME, self.seal(ROOT_AAD, &bytes)?])?;
        Ok(())
    }
    pub(super) fn state_commitment(&self) -> Result<Vec<u8>> {
        self.state_root()?.commitment()
    }
    fn load_state_node(&self, reference: &Reference) -> Result<IndexNode> {
        let id = reference
            .id
            .as_deref()
            .context("missing object state node")?;
        let bytes: Option<Vec<u8>> = self.conn.query_row(
            "SELECT CASE WHEN length(node)<=65536 THEN node ELSE NULL END FROM object_state WHERE id=?1", [id], |row| row.get(0)
        ).optional()?.flatten();
        let node: IndexNode =
            serde_json::from_slice(&bytes.context("missing or oversized object state node")?)?;
        if node.id != id || node.reference()? != *reference {
            bail!("object state index authentication failed");
        }
        Ok(node)
    }
    fn save_state_node(&self, node: &IndexNode) -> Result<Reference> {
        let reference = node.reference()?;
        let bytes = serde_json::to_vec(node)?;
        if bytes.len() > 65536 {
            bail!("object state node exceeds size limit");
        }
        self.conn.execute("INSERT INTO object_state(id,node) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET node=excluded.node", params![node.id, bytes])?;
        Ok(reference)
    }
    fn rotate_state_left(&self, mut node: IndexNode) -> Result<Reference> {
        let mut right = self.load_state_node(&node.right)?;
        node.right = right.left;
        right.left = self.save_state_node(&node)?;
        self.save_state_node(&right)
    }
    fn rotate_state_right(&self, mut node: IndexNode) -> Result<Reference> {
        let mut left = self.load_state_node(&node.left)?;
        node.left = left.right;
        left.right = self.save_state_node(&node)?;
        self.save_state_node(&left)
    }
    fn balance_state_node(&self, mut node: IndexNode) -> Result<Reference> {
        if node.left.height > node.right.height + 1 {
            let mut left = self.load_state_node(&node.left)?;
            if left.right.height > left.left.height {
                let mut pivot = self.load_state_node(&left.right)?;
                left.right = pivot.left;
                node.left = pivot.right;
                pivot.left = self.save_state_node(&left)?;
                pivot.right = self.save_state_node(&node)?;
                return self.save_state_node(&pivot);
            }
            self.rotate_state_right(node)
        } else if node.right.height > node.left.height + 1 {
            let mut right = self.load_state_node(&node.right)?;
            if right.left.height > right.right.height {
                let mut pivot = self.load_state_node(&right.left)?;
                node.right = pivot.left;
                right.left = pivot.right;
                pivot.left = self.save_state_node(&node)?;
                pivot.right = self.save_state_node(&right)?;
                return self.save_state_node(&pivot);
            }
            self.rotate_state_left(node)
        } else {
            self.save_state_node(&node)
        }
    }
    fn update_state_path(&self, current: &Reference, replacement: IndexNode) -> Result<Reference> {
        if current.id.is_none() {
            return self.save_state_node(&replacement);
        }
        let mut node = self.load_state_node(current)?;
        match replacement.id.cmp(&node.id) {
            std::cmp::Ordering::Less => {
                node.left = self.update_state_path(&node.left, replacement)?
            }
            std::cmp::Ordering::Greater => {
                node.right = self.update_state_path(&node.right, replacement)?
            }
            std::cmp::Ordering::Equal => {
                node.owner = replacement.owner;
                node.rowid = replacement.rowid;
                node.value_hash = replacement.value_hash;
            }
        }
        self.balance_state_node(node)
    }
    pub(super) fn index_object_record(
        &self,
        id: &str,
        owner: &str,
        rowid: i64,
        sealed: &[u8],
    ) -> Result<()> {
        let root = self.state_root()?;
        let node = IndexNode {
            id: id.to_owned(),
            owner: owner.to_owned(),
            rowid,
            value_hash: crate::crypto::sha256(sealed),
            left: Reference::empty(),
            right: Reference::empty(),
        };
        self.set_state_root(self.update_state_path(&root, node)?)
    }
    /// Detach the smallest node of a non-empty subtree. Its row is rewritten by
    /// the caller, which re-saves it in the removed node's position.
    fn detach_min_state_node(&self, current: &Reference) -> Result<(IndexNode, Reference)> {
        let mut node = self.load_state_node(current)?;
        if node.left.id.is_none() {
            let right = std::mem::replace(&mut node.right, Reference::empty());
            return Ok((node, right));
        }
        let (min, left) = self.detach_min_state_node(&node.left)?;
        node.left = left;
        Ok((min, self.balance_state_node(node)?))
    }
    fn remove_state_path(&self, current: &Reference, id: &str) -> Result<Reference> {
        if current.id.is_none() {
            bail!("object state index has no record to remove");
        }
        let mut node = self.load_state_node(current)?;
        match id.cmp(&node.id) {
            std::cmp::Ordering::Less => node.left = self.remove_state_path(&node.left, id)?,
            std::cmp::Ordering::Greater => node.right = self.remove_state_path(&node.right, id)?,
            std::cmp::Ordering::Equal => {
                self.conn
                    .execute("DELETE FROM object_state WHERE id=?1", [&node.id])?;
                return match (node.left.id.is_some(), node.right.id.is_some()) {
                    (false, _) => Ok(node.right.clone()),
                    (true, false) => Ok(node.left.clone()),
                    (true, true) => {
                        let (mut successor, right) = self.detach_min_state_node(&node.right)?;
                        successor.left = node.left.clone();
                        successor.right = right;
                        self.balance_state_node(successor)
                    }
                };
            }
        }
        self.balance_state_node(node)
    }
    /// Remove one owner's record and its index node; the new root is committed
    /// by the next audit event exactly like an insertion.
    pub(super) fn remove_object_record(&self, owner: &str, id: &str) -> Result<()> {
        self.authenticated_record(owner, id)?
            .context("cannot remove a missing object or a different owner's object")?;
        let root = self.state_root()?;
        let root = self.remove_state_path(&root, id)?;
        if self.conn.execute(
            "DELETE FROM objects WHERE id=?1 AND owner=?2",
            params![id, owner],
        )? != 1
        {
            bail!("object record removal failed");
        }
        self.set_state_root(root)
    }
    /// The authenticated owner, rowid and record hash of an identifier.
    pub(super) fn find_record(&self, id: &str) -> Result<Option<(String, i64, [u8; 32])>> {
        Ok(self
            .find_state_node(id)?
            .map(|node| (node.owner, node.rowid, node.value_hash)))
    }
    fn find_state_node(&self, id: &str) -> Result<Option<IndexNode>> {
        let mut reference = self.state_root()?;
        for _ in 0..=64 {
            if reference.id.is_none() {
                return Ok(None);
            }
            let node = self.load_state_node(&reference)?;
            match id.cmp(&node.id) {
                std::cmp::Ordering::Less => reference = node.left,
                std::cmp::Ordering::Greater => reference = node.right,
                std::cmp::Ordering::Equal => return Ok(Some(node)),
            }
        }
        bail!("object state index exceeds height limit")
    }
    fn read_state_record(&self, node: &IndexNode) -> Result<Vec<u8>> {
        self.walked_record(&node.id, &node.owner, node.rowid, &node.value_hash)
    }
    /// The sealed record of an index node already authenticated from the
    /// root, such as one `walk_state` visits: one row read, no second
    /// descent of the index.
    pub(super) fn walked_record(
        &self,
        id: &str,
        node_owner: &str,
        node_rowid: i64,
        value_hash: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let record: Option<(String, i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT owner,rowid,sealed FROM objects WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (owner, rowid, sealed) = record.context("authenticated object record is missing")?;
        if owner != node_owner
            || rowid != node_rowid
            || !bool::from(crate::crypto::sha256(&sealed).ct_eq(value_hash))
        {
            bail!("object record differs from its authenticated state");
        }
        Ok(sealed)
    }
    pub(super) fn authenticated_record(&self, owner: &str, id: &str) -> Result<Option<Vec<u8>>> {
        let Some(node) = self.find_state_node(id)? else {
            return Ok(None);
        };
        if node.owner != owner {
            return Ok(None);
        }
        Ok(Some(self.read_state_record(&node)?))
    }
    pub(super) fn authenticated_owner(&self, id: &str) -> Result<Option<String>> {
        Ok(self.find_state_node(id)?.map(|node| node.owner))
    }
    /// Walk authenticated metadata in ID order. Only the caller's selected records
    /// need decryption; absence and inventory come from the authenticated tree.
    pub(super) fn walk_state(
        &self,
        mut visit: impl FnMut(&str, &str, i64, &[u8; 32]) -> Result<bool>,
    ) -> Result<()> {
        let mut stack = Vec::new();
        let mut current = self.state_root()?;
        let mut previous: Option<String> = None;
        loop {
            while current.id.is_some() {
                if stack.len() >= 64 {
                    bail!("object state index exceeds height limit");
                }
                let node = self.load_state_node(&current)?;
                current = node.left.clone();
                stack.push(node);
            }
            let Some(node) = stack.pop() else {
                return Ok(());
            };
            if previous.as_ref().is_some_and(|id| id >= &node.id) {
                bail!("object state index ordering failed");
            }
            if visit(&node.id, &node.owner, node.rowid, &node.value_hash)? {
                return Ok(());
            }
            previous = Some(node.id);
            current = node.right;
        }
    }
    pub(super) fn verify_object_state(&self) -> Result<()> {
        let root = self.state_root()?;
        let (objects, nodes): (i64, i64) = self.conn.query_row(
            "SELECT (SELECT COUNT(*) FROM objects),(SELECT COUNT(*) FROM object_state)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if objects != i64::try_from(root.count)? || nodes != i64::try_from(root.count)? {
            bail!("object state inventory differs from authenticated root");
        }
        let mut count = 0u64;
        self.walk_state(|id, owner, rowid, value_hash| {
            let record = IndexNode {
                id: id.to_owned(),
                owner: owner.to_owned(),
                rowid,
                value_hash: *value_hash,
                left: Reference::empty(),
                right: Reference::empty(),
            };
            let sealed = self.read_state_record(&record)?;
            let plaintext = self.unseal(&Self::aad(owner, id), &sealed)?;
            Self::validate_record(owner, id, &plaintext)?;
            count += 1;
            Ok(false)
        })?;
        if count != root.count {
            bail!("object state traversal count mismatch");
        }
        Ok(())
    }
    pub(super) fn with_state_read<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        let transaction = self
            .conn
            .is_autocommit()
            .then(|| self.conn.unchecked_transaction())
            .transpose()?;
        self.check_live_history()?;
        // A read-only open of an older store has no object index to bind yet.
        if transaction.is_some() && !self.legacy() {
            self.check_committed_state()?;
        }
        let result = action()?;
        if let Some(transaction) = transaction {
            let tip = self.history_tip()?;
            transaction.commit()?;
            self.observe_history(tip);
        }
        Ok(result)
    }
    pub(super) fn mutate_state<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        let standalone = self.conn.is_autocommit();
        if standalone {
            self.begin()?;
        }
        let _rollback = standalone.then(|| StandaloneRollback(&self.conn));
        self.conn.execute_batch("SAVEPOINT object_state_mutation")?;
        let result = action();
        match result {
            Ok(value) => {
                self.conn.execute_batch("RELEASE object_state_mutation")?;
                if standalone {
                    self.commit()?;
                }
                Ok(value)
            }
            Err(error) => {
                if let Err(rollback) = self.conn.execute_batch(
                    "ROLLBACK TO object_state_mutation; RELEASE object_state_mutation",
                ) {
                    bail!(
                        "object state mutation failed: {error:#}; savepoint rollback failed: {rollback:#}"
                    );
                }
                if standalone {
                    self.rollback()?;
                }
                Err(error)
            }
        }
    }
    pub(super) fn audit_has_state(&self) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('audit') WHERE name='state_root'",
            [],
            |row| row.get::<_, u32>(0),
        )? == 1)
    }
    pub(super) fn check_committed_state(&self) -> Result<()> {
        if !self.committed_state_matches()? {
            bail!("object state is not bound to the current audit event");
        }
        Ok(())
    }
    pub(super) fn committed_state_matches(&self) -> Result<bool> {
        let root = self.state_root()?;
        let event = self.conn.query_row("SELECT seq,timestamp,principal,operation,object_id,status,previous,mac,state_root FROM audit ORDER BY seq DESC LIMIT 1", [], |row| {
            Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,String>(2)?,row.get::<_,u32>(3)?,row.get::<_,Option<String>>(4)?,row.get::<_,u32>(5)?,row.get::<_,Vec<u8>>(6)?,row.get::<_,Vec<u8>>(7)?,row.get::<_,Option<Vec<u8>>>(8)?))
        }).optional()?;
        match event {
            None => Ok(root == Reference::empty()),
            Some((seq, time, principal, op, id, status, previous, mac, Some(state))) => {
                let expected = self.audit_mac(
                    seq,
                    time,
                    &principal,
                    op,
                    id.as_deref(),
                    status,
                    &previous,
                    Some(&state),
                )?;
                if !bool::from(mac.ct_eq(&expected)) {
                    bail!("current audit event authentication failed");
                }
                Ok(bool::from(state.ct_eq(&root.commitment()?)))
            }
            _ => bail!("object state has no current audit binding"),
        }
    }
    /// Used only in checked migration and fresh rotation targets.
    pub(super) fn build_object_state(&self) -> Result<()> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM object_state", [], |row| row.get(0))?;
        if count != 0 {
            bail!("object state index is already initialized");
        }
        self.set_state_root(Reference::empty())?;
        let mut statement = self
            .conn
            .prepare("SELECT id,owner,rowid,sealed FROM objects ORDER BY rowid")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let owner: String = row.get(1)?;
            let rowid = row.get(2)?;
            let sealed: Vec<u8> = row.get(3)?;
            let plaintext = self.unseal(&Self::aad(&owner, &id), &sealed)?;
            Self::validate_record(&owner, &id, &plaintext)?;
            self.index_object_record(&id, &owner, rowid, &sealed)?;
        }
        Ok(())
    }
    pub(super) fn migrate_object_state(&self) -> Result<()> {
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let existing: u32 = self.conn.query_row("SELECT (SELECT COUNT(*) FROM sqlite_schema WHERE name='object_state')+(SELECT COUNT(*) FROM meta WHERE name='object-state-root')", [], |row| row.get(0))?;
        if existing != 0 || self.audit_has_state()? {
            bail!("object state data exists under an older schema; downgrade refused");
        }
        self.verify_audit()?;
        self.conn.execute_batch("ALTER TABLE audit ADD COLUMN state_root BLOB; CREATE TABLE object_state(id TEXT PRIMARY KEY,node BLOB NOT NULL);")?;
        self.build_object_state()?;
        let nonempty: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM objects) OR EXISTS(SELECT 1 FROM audit)",
            [],
            |row| row.get(0),
        )?;
        if nonempty {
            self.audit("keytend-kmip-server/storage-migration", 0, None, 0)?;
        }
        self.conn.execute_batch("PRAGMA user_version=18")?;
        self.verify_audit()?;
        self.check_committed_state()?;
        self.verify_object_state()?;
        transaction.commit()?;
        Ok(())
    }
}
