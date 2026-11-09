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

use keytend_kmip_server::store::Store;
use rusqlite::Connection;
use std::path::{Path, PathBuf};

struct Fixture {
    dir: tempfile::TempDir,
    database: PathBuf,
    key: PathBuf,
    store: Store,
}
fn write_key(path: &Path, byte: u8) {
    std::fs::write(path, [byte; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("store.sqlite");
        let key = dir.path().join("master.key");
        write_key(&key, 0x37);
        let store = Store::open(&database, &key).unwrap();
        Self {
            dir,
            database,
            key,
            store,
        }
    }
    fn checkpoint(&self, name: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        self.store.write_audit_checkpoint(&path, None).unwrap();
        path
    }
    fn audit(&self, id: &str) {
        self.store.audit("alice", 24, Some(id), 0).unwrap();
    }
    fn sql(&self) -> Connection {
        Connection::open(&self.database).unwrap()
    }
}

#[test]
fn immutable_checkpoint_allows_later_events_and_empty_histories() {
    let f = Fixture::new();
    let zero = f.checkpoint("zero.json");
    f.store.verify_audit_checkpoint(&zero).unwrap();
    f.audit("one");
    f.store.verify_audit_checkpoint(&zero).unwrap();
    let one = f.dir.path().join("one.json");
    f.store.write_audit_checkpoint(&one, Some(&zero)).unwrap();
    let bytes = std::fs::read(&one).unwrap();
    f.audit("two");
    f.store.verify_audit_checkpoint(&one).unwrap();
    assert!(f.store.write_audit_checkpoint(&one, Some(&zero)).is_err());
    assert_eq!(std::fs::read(one).unwrap(), bytes);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&zero, f.dir.path().join("projected.json")).unwrap();
        f.store
            .verify_audit_checkpoint(&f.dir.path().join("projected.json"))
            .unwrap();
    }
}

#[test]
fn whole_snapshot_rollback_and_valid_prefix_truncation_are_rejected() {
    let f = Fixture::new();
    f.audit("one");
    let old = f.dir.path().join("old.sqlite");
    f.store.backup(&old).unwrap();
    f.audit("two");
    let floor = f.checkpoint("floor.json");
    f.audit("three");
    let restored = Store::open(&old, &f.key).unwrap();
    restored.verify_integrity().unwrap();
    assert!(restored.verify_audit_checkpoint(&floor).is_err());
    let output = f.dir.path().join("lower.json");
    assert!(
        restored
            .write_audit_checkpoint(&output, Some(&floor))
            .is_err()
    );
    assert!(!output.exists());
    f.sql()
        .execute("DELETE FROM audit WHERE seq>1", [])
        .unwrap();
    assert!(f.store.verify_audit().is_err()); // The live floor detects truncation.
    // A fresh handle can still authenticate the valid prefix, but must apply
    // the independently retained floor to reject rollback across a restart.
    let reopened = Store::open(&f.database, &f.key).unwrap();
    reopened.verify_audit().unwrap();
    assert!(reopened.verify_audit_checkpoint(&floor).is_err());
    assert!(f.store.verify_audit_checkpoint(&floor).is_err());
}

#[test]
fn a_valid_alternate_branch_at_the_same_sequence_is_rejected() {
    let f = Fixture::new();
    f.audit("prefix");
    let fork = f.dir.path().join("fork.sqlite");
    f.store.backup(&fork).unwrap();
    f.audit("branch A");
    let floor = f.checkpoint("floor.json");
    let alternate = Store::open(&fork, &f.key).unwrap();
    alternate.audit("alice", 24, Some("branch B"), 0).unwrap();
    alternate.verify_audit().unwrap();
    assert!(alternate.verify_audit_checkpoint(&floor).is_err());
}

#[test]
fn store_identity_and_storage_key_generation_are_bound() {
    let f = Fixture::new();
    f.audit("one");
    let floor = f.checkpoint("floor.json");
    let other = Store::open(&f.dir.path().join("other.sqlite"), &f.key).unwrap();
    other.audit("alice", 24, Some("one"), 0).unwrap();
    assert!(other.verify_audit_checkpoint(&floor).is_err());
    let next = f.dir.path().join("next.key");
    write_key(&next, 0x92);
    let output = f.dir.path().join("rotated.sqlite");
    f.store
        .rotate_master_key_checked(&next, &output, Some(&floor))
        .unwrap();
    let rotated = Store::open(&output, &next).unwrap();
    assert!(rotated.verify_audit_checkpoint(&floor).is_err());
    let new_floor = f.dir.path().join("new-floor.json");
    rotated.write_audit_checkpoint(&new_floor, None).unwrap();
    rotated.verify_audit_checkpoint(&new_floor).unwrap();
    f.store.verify_audit_checkpoint(&floor).unwrap();
    assert!(f.store.verify_audit_checkpoint(&new_floor).is_err());
}

#[test]
fn rotation_cannot_reauthenticate_a_rollback_older_than_the_required_floor() {
    let f = Fixture::new();
    f.audit("one");
    let snapshot = f.dir.path().join("old.sqlite");
    f.store.backup(&snapshot).unwrap();
    f.audit("two");
    let floor = f.checkpoint("floor.json");
    let next = f.dir.path().join("next.key");
    write_key(&next, 0x92);
    let output = f.dir.path().join("must-not-exist.sqlite");
    let old = Store::open(&snapshot, &f.key).unwrap();
    assert!(
        old.rotate_master_key_checked(&next, &output, Some(&floor))
            .is_err()
    );
    assert!(!output.exists());
    old.verify_integrity().unwrap();
}

#[test]
fn tampered_missing_oversized_and_unknown_checkpoint_fields_fail_closed() {
    let f = Fixture::new();
    f.audit("one");
    let checkpoint = f.checkpoint("good.json");
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(checkpoint).unwrap()).unwrap();
    let path = f.dir.path().join("bad.json");
    assert!(f.store.verify_audit_checkpoint(&path).is_err());
    for (field, value) in [
        ("version", serde_json::json!(2)),
        ("sequence", serde_json::json!(-1)),
        ("sequence", serde_json::json!(0)),
        ("head_mac", serde_json::json!("00".repeat(32))),
        ("store_id", serde_json::json!("00".repeat(32))),
        ("authentication", serde_json::json!("00".repeat(32))),
        ("authentication", serde_json::json!("zz".repeat(32))),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            f.store.verify_audit_checkpoint(&path).is_err(),
            "accepted modified {field}"
        );
    }
    std::fs::write(&path, vec![b' '; 4097]).unwrap();
    assert!(f.store.verify_audit_checkpoint(&path).is_err());
    std::fs::write(&path, b"{}").unwrap();
    assert!(f.store.verify_audit_checkpoint(&path).is_err());
}

#[test]
fn current_chain_corruption_after_the_floor_is_still_rejected() {
    let f = Fixture::new();
    f.audit("one");
    let checkpoint = f.checkpoint("floor.json");
    f.audit("two");
    f.sql()
        .execute("UPDATE audit SET status=1 WHERE seq=2", [])
        .unwrap();
    assert!(f.store.verify_audit_checkpoint(&checkpoint).is_err());
    let path = f.dir.path().join("corrupt-export.json");
    assert!(f.store.write_audit_checkpoint(&path, None).is_err());
    assert!(!path.exists());
}
