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

//! Hidden server records: configuration and state the server keeps in the
//! object store without exposing it as managed objects.
//!
//! A record is an `Object` whose owner is a reserved namespace that no
//! policy principal or credential identity can name (policy names contain no
//! NUL, and credential-identity owners start with a principal name), so
//! Get, Locate and every other managed-object operation never reach it. Its
//! payload is `material`, sealed and authenticated like every object, and
//! covered by the object-state index, backups, master-key rotation and
//! `check-store`. Record identifiers contain NUL, which Import refuses in
//! client-chosen identifiers (transfer.rs), so a client cannot occupy one.
use super::*;

/// Object types of hidden records (outside every edition's Object Type
/// values; never returned to clients).
pub(super) const PROVISIONING_RECORD: u32 = 0x8000_0035;
pub(super) const DEFAULTS_RECORD: u32 = 0x8000_0036;
pub(super) const CONSTRAINTS_RECORD: u32 = 0x8000_0037;
/// Reserved owners of server-wide records.
pub(super) const PROVISIONING_OWNER: &str = "\0provisioning";
pub(super) const SERVER_DEFAULTS_OWNER: &str = "\0server\0defaults";
pub(super) const SERVER_CONSTRAINTS_OWNER: &str = "\0server\0constraints";

fn record(owner: &str, id: &str, kind: u32, material: Vec<u8>, time: i64) -> Object {
    Object {
        id: id.to_owned(),
        owner: owner.to_owned(),
        object_type: kind,
        secret_type: 2,
        opaque_type: opaque::LEGACY_TYPE,
        pgp_version: pgp::DEFAULT_VERSION,
        certificate_type: 1,
        format: 0,
        algorithm: 0,
        bits: 0,
        usage: 0,
        protection_mask: protection::SOFTWARE,
        usage_consumed: false,
        replacement_id: None,
        wrapped: None,
        imported: false,
        metadata: Default::default(),
        split: None,
        state: 1,
        material,
        attrs: vec![],
        attribute_indices: Default::default(),
        created: time,
        updated: time,
    }
}

impl Engine {
    /// The material of a record, or None if it does not exist.
    pub(super) fn read_record(&self, owner: &str, id: &str) -> R<Option<Vec<u8>>> {
        Ok(self
            .store
            .get(owner, id)?
            .map(|record| record.material.clone()))
    }
    /// Create or replace a record.
    pub(super) fn write_record(
        &mut self,
        owner: &str,
        id: &str,
        kind: u32,
        material: Vec<u8>,
    ) -> R<()> {
        let time = now();
        match self.store.get(owner, id)? {
            Some(mut existing) => {
                existing.material = material;
                existing.updated = time;
                self.store.put(&existing)?;
            }
            None => self
                .store
                .insert(&record(owner, id, kind, material, time))?,
        }
        Ok(())
    }
    /// Remove a record; a missing record is not an error.
    pub(super) fn remove_record(&mut self, owner: &str, id: &str) -> R<()> {
        if self.store.get(owner, id)?.is_some() {
            self.store.remove(owner, id)?;
        }
        Ok(())
    }
    /// Every record of a reserved owner, as (identifier, material).
    pub(super) fn list_records(&self, owner: &str) -> R<Vec<(String, Vec<u8>)>> {
        Ok(self
            .store
            .list(owner)?
            .into_iter()
            .map(|record| (record.id.clone(), record.material.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_created_replaced_listed_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("master");
        std::fs::write(&master, [9; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&dir.path().join("s.sqlite"), &master).unwrap();
        let mut engine = Engine::new(store, false);
        let owner = "\0test";
        assert!(engine.read_record(owner, "r\0one").unwrap().is_none());
        engine
            .write_record(owner, "r\0one", 0x8000_00ff, b"one".to_vec())
            .unwrap();
        engine
            .write_record(owner, "r\0one", 0x8000_00ff, b"two".to_vec())
            .unwrap();
        engine
            .write_record(owner, "r\0two", 0x8000_00ff, b"three".to_vec())
            .unwrap();
        assert_eq!(
            engine.read_record(owner, "r\0one").unwrap().unwrap(),
            b"two"
        );
        let mut listed = engine.list_records(owner).unwrap();
        listed.sort();
        assert_eq!(
            listed,
            vec![
                ("r\0one".to_owned(), b"two".to_vec()),
                ("r\0two".to_owned(), b"three".to_vec())
            ]
        );
        engine.remove_record(owner, "r\0one").unwrap();
        engine.remove_record(owner, "r\0one").unwrap();
        assert!(engine.read_record(owner, "r\0one").unwrap().is_none());
        // Managed-object owners never see records.
        assert!(engine.store.list("alice").unwrap().is_empty());
    }
}
