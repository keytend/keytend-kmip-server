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

use keytend_kmip_server::store::{Object, Store};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

struct Fixture {
    directory: tempfile::TempDir,
    path: PathBuf,
    key: PathBuf,
    store: Store,
}
fn object() -> Object {
    serde_json::from_value(serde_json::json!({
        "id":"key", "owner":"alice", "object_type":2, "format":1,
        "algorithm":3, "bits":256, "usage":12, "state":2,
        "material":vec![42;32], "attrs":[], "created":1234, "updated":1234
    }))
    .unwrap()
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("live.sqlite");
        let key = directory.path().join("master.key");
        std::fs::write(&key, [0x51; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&path, &key).unwrap();
        Self {
            directory,
            path,
            key,
            store,
        }
    }
    fn backup(&self, name: &str) -> PathBuf {
        let path = self.directory.path().join(name);
        self.store.backup(&path).unwrap();
        path
    }
    /// Replace every persistent table through another SQLite connection, with
    /// valid snapshot bytes and normal WAL visibility. The live Store stays open.
    fn replay(&self, snapshot: &Path) {
        let sql = Connection::open(&self.path).unwrap();
        sql.execute("ATTACH DATABASE ?1 AS old", [snapshot.to_str().unwrap()])
            .unwrap();
        sql.execute_batch("BEGIN IMMEDIATE;
            DELETE FROM objects; DELETE FROM object_state; DELETE FROM audit; DELETE FROM meta;
            INSERT INTO objects(rowid,id,owner,sealed) SELECT rowid,id,owner,sealed FROM old.objects;
            INSERT INTO object_state SELECT * FROM old.object_state;
            INSERT INTO audit SELECT * FROM old.audit;
            INSERT INTO meta SELECT * FROM old.meta;
            COMMIT;").unwrap();
    }
}

#[test]
fn whole_valid_rollback_cannot_resurrect_material_and_failure_stays_latched() {
    let f = Fixture::new();
    let mut key = object();
    f.store.insert(&key).unwrap();
    let old = f.backup("old.sqlite");
    key.state = 5;
    key.material.clear();
    key.usage_consumed = true;
    f.store.put(&key).unwrap();
    let current = f.backup("current.sqlite");
    f.replay(&old);
    Store::open(&f.path, &f.key)
        .unwrap()
        .verify_integrity()
        .unwrap();
    assert!(
        format!("{:#}", f.store.get("alice", "key").err().unwrap()).contains("live store history")
    );
    assert!(!f.store.healthy());
    assert!(f.store.put(&key).is_err());
    assert!(f.store.verify_audit().is_err());
    let output = f.directory.path().join("forbidden.sqlite");
    assert!(f.store.backup(&output).is_err());
    assert!(!output.exists());
    let checkpoint = f.directory.path().join("forbidden.json");
    assert!(f.store.write_audit_checkpoint(&checkpoint, None).is_err());
    assert!(!checkpoint.exists());
    f.replay(&current);
    assert!(f.store.get("alice", "key").is_err());
    assert!(!f.store.healthy());
    let recovered = Store::open(&f.path, &f.key).unwrap();
    assert_eq!(recovered.get("alice", "key").unwrap().unwrap().state, 5);
}

#[test]
fn undone_audit_and_object_reads_do_not_advance_committed_floor() {
    let f = Fixture::new();
    let mut key = object();
    f.store.insert(&key).unwrap();
    f.store.begin().unwrap();
    key.material.fill(7);
    f.store.put(&key).unwrap();
    f.store.audit("alice", 2, Some("key"), 0).unwrap();
    assert_eq!(
        f.store.get("alice", "key").unwrap().unwrap().material,
        vec![7; 32]
    );
    f.store.rollback().unwrap();
    assert!(f.store.healthy());
    assert_eq!(
        f.store.get("alice", "key").unwrap().unwrap().material,
        vec![42; 32]
    );
    f.store.put(&key).unwrap();
    f.store.verify_integrity().unwrap();
}

#[test]
fn reading_a_valid_external_extension_advances_the_floor() {
    let f = Fixture::new();
    let old = f.backup("empty.sqlite");
    let other = Store::open(&f.path, &f.key).unwrap();
    other.insert(&object()).unwrap();
    assert!(f.store.get("alice", "key").unwrap().is_some());
    f.replay(&old);
    assert!(f.store.get("alice", "key").is_err());
}

#[test]
fn longer_authentic_alternate_branch_is_refused() {
    let f = Fixture::new();
    let mut key = object();
    f.store.insert(&key).unwrap();
    let fork = f.backup("fork.sqlite");
    key.material.fill(8);
    f.store.put(&key).unwrap();
    let other = Store::open(&fork, &f.key).unwrap();
    key.material.fill(9);
    other.put(&key).unwrap();
    key.material.fill(10);
    other.put(&key).unwrap();
    other.verify_integrity().unwrap();
    f.replay(&fork);
    assert!(format!("{:#}", f.store.get("alice", "key").err().unwrap()).contains("diverges"));
}

#[test]
fn valid_new_head_does_not_hide_a_missing_unseen_link() {
    let f = Fixture::new();
    f.store.insert(&object()).unwrap();
    let other = Store::open(&f.path, &f.key).unwrap();
    other.audit("external", 24, None, 0).unwrap();
    other.audit("external", 24, None, 0).unwrap();
    let sql = Connection::open(&f.path).unwrap();
    sql.execute("DELETE FROM audit WHERE seq=2", []).unwrap();
    assert!(
        format!("{:#}", f.store.get("alice", "key").err().unwrap())
            .contains("extension authentication")
    );
}

#[test]
fn backup_checks_live_floor_before_publishing_an_otherwise_valid_snapshot() {
    let f = Fixture::new();
    let old = f.backup("empty.sqlite");
    f.store.insert(&object()).unwrap();
    f.replay(&old);
    let output = f.directory.path().join("must-not-publish.sqlite");
    assert!(f.store.backup(&output).is_err());
    assert!(!output.exists());
}

#[test]
fn health_check_detects_rollback_without_a_prior_object_request() {
    let f = Fixture::new();
    let old = f.backup("empty.sqlite");
    f.store.insert(&object()).unwrap();
    f.replay(&old);
    assert!(!f.store.healthy());
    assert!(f.store.get("alice", "key").is_err());
}

#[test]
fn another_empty_store_under_the_same_key_cannot_replace_live_identity() {
    let f = Fixture::new();
    let other_path = f.directory.path().join("unrelated.sqlite");
    let other = Store::open(&other_path, &f.key).unwrap();
    other.verify_integrity().unwrap();
    f.replay(&other_path);
    assert!(!f.store.healthy());
}
