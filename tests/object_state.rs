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

use keytend_kmip_server::store::{Object, STORAGE_SCHEMA, Store};
use rusqlite::Connection;
#[path = "support/legacy.rs"]
mod legacy;

struct Fixture {
    dir: tempfile::TempDir,
    path: std::path::PathBuf,
    key: std::path::PathBuf,
    store: Store,
}
fn object(id: &str) -> Object {
    serde_json::from_value(
        serde_json::json!({"id":id,"owner":"alice","object_type":2,"format":1,
        "algorithm":3,"bits":256,"usage":12,"state":2,"material":vec![42;32],"attrs":[],
        "created":1234,"updated":1234}),
    )
    .unwrap()
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.sqlite");
        let key = dir.path().join("master.key");
        std::fs::write(&key, [0x31; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&path, &key).unwrap();
        Self {
            dir,
            path,
            key,
            store,
        }
    }
    fn sql(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }
    fn rejected(&self) {
        assert!(self.store.verify_integrity().is_err());
        assert!(Store::open(&self.path, &self.key).is_err());
        let output = self.dir.path().join("refused-backup.sqlite");
        assert!(self.store.backup(&output).is_err());
        assert!(!output.exists());
        let checkpoint = self.dir.path().join("refused-checkpoint.json");
        assert!(
            self.store
                .write_audit_checkpoint(&checkpoint, None)
                .is_err()
        );
        assert!(!checkpoint.exists());
    }
}

#[test]
fn old_valid_ciphertext_cannot_restore_destroyed_key_or_reset_usage() {
    let f = Fixture::new();
    let mut o = object("key");
    f.store.insert(&o).unwrap();
    let old: Vec<u8> = Connection::open(&f.path)
        .unwrap()
        .query_row("SELECT sealed FROM objects", [], |r| r.get(0))
        .unwrap();
    o.state = 5;
    o.material.clear();
    o.usage_consumed = true;
    f.store.put(&o).unwrap();
    f.sql()
        .execute("UPDATE objects SET sealed=?1", [old])
        .unwrap();
    f.store.verify_audit().unwrap(); // The history remains authentic and current.
    assert!(f.store.get("alice", "key").is_err());
    assert!(f.store.put(&o).is_err());
    assert!(f.store.list("alice").is_err());
    f.rejected();
}

#[test]
fn replaying_old_tree_and_root_with_current_history_is_rejected() {
    let f = Fixture::new();
    let mut o = object("key");
    f.store.insert(&o).unwrap();
    let sql = f.sql();
    let root: Vec<u8> = sql
        .query_row(
            "SELECT value FROM meta WHERE name='object-state-root'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let node: Vec<u8> = sql
        .query_row("SELECT node FROM object_state", [], |r| r.get(0))
        .unwrap();
    let ciphertext: Vec<u8> = sql
        .query_row("SELECT sealed FROM objects", [], |r| r.get(0))
        .unwrap();
    o.usage_consumed = true;
    f.store.put(&o).unwrap();
    sql.execute(
        "UPDATE meta SET value=?1 WHERE name='object-state-root'",
        [root],
    )
    .unwrap();
    sql.execute("UPDATE object_state SET node=?1", [node])
        .unwrap();
    sql.execute("UPDATE objects SET sealed=?1", [ciphertext])
        .unwrap();
    f.store.verify_audit().unwrap();
    assert!(f.store.get("alice", "key").is_err());
    assert!(f.store.owner_of("missing").is_err());
    assert!(f.store.begin().is_err());
    f.rejected();
}

#[test]
fn deleted_records_are_integrity_errors_instead_of_authenticated_absence() {
    let f = Fixture::new();
    f.store.insert(&object("key")).unwrap();
    f.sql().execute("DELETE FROM objects", []).unwrap();
    assert!(f.store.get("alice", "key").is_err());
    assert!(f.store.list("alice").is_err());
    f.rejected();
}

#[test]
fn owner_rowid_and_ciphertext_substitution_are_rejected() {
    for statement in [
        "UPDATE objects SET owner='bob'",
        "UPDATE objects SET rowid=rowid+1",
        "UPDATE objects SET sealed=randomblob(80)",
    ] {
        let f = Fixture::new();
        f.store.insert(&object("key")).unwrap();
        f.sql().execute(statement, []).unwrap();
        assert!(f.store.get("alice", "key").is_err(), "{statement}");
        f.rejected();
    }
}

#[test]
fn missing_changed_and_extra_index_nodes_and_objects_are_rejected() {
    for statement in [
        "DELETE FROM object_state",
        "UPDATE object_state SET node=x'7b7d'",
        "INSERT INTO object_state VALUES('extra',x'7b7d')",
        "INSERT INTO objects VALUES('extra','alice',x'00')",
        "DELETE FROM meta WHERE name='object-state-root'",
        "UPDATE meta SET value=randomblob(64) WHERE name='object-state-root'",
        "UPDATE audit SET state_root=randomblob(32)",
    ] {
        let f = Fixture::new();
        f.store.insert(&object("key")).unwrap();
        f.sql().execute(statement, []).unwrap();
        f.rejected();
    }
}

#[test]
fn all_four_rotation_shapes_updates_and_authenticated_absence_survive_restart() {
    for order in [
        ["a", "b", "c"],
        ["c", "b", "a"],
        ["c", "a", "b"],
        ["a", "c", "b"],
    ] {
        let f = Fixture::new();
        for id in order {
            f.store.insert(&object(id)).unwrap();
            f.store.verify_integrity().unwrap();
        }
        assert!(f.store.get("alice", "absent").unwrap().is_none());
        assert!(f.store.get("bob", "b").unwrap().is_none());
        let mut o = object("b");
        o.usage_consumed = true;
        f.store.put(&o).unwrap();
        let reopened = Store::open(&f.path, &f.key).unwrap();
        assert_eq!(reopened.list("alice").unwrap().len(), 3);
        assert!(reopened.get("alice", "b").unwrap().unwrap().usage_consumed);
    }
}

#[test]
fn larger_tree_permutation_updates_and_duplicate_failure_preserve_integrity() {
    let f = Fixture::new();
    for n in 0..192 {
        f.store
            .insert(&object(&format!("{:03}", (n * 73) % 192)))
            .unwrap();
    }
    f.store.verify_integrity().unwrap();
    for n in (0..192).step_by(3) {
        let mut o = object(&format!("{n:03}"));
        o.usage_consumed = true;
        f.store.put(&o).unwrap();
    }
    assert!(f.store.insert(&object("073")).is_err());
    assert!(f.store.put(&object("absent")).is_err());
    f.store.verify_integrity().unwrap();
    assert_eq!(f.store.list("alice").unwrap().len(), 192);
    let reopened = Store::open(&f.path, &f.key).unwrap();
    for n in 0..192 {
        assert_eq!(
            reopened
                .get("alice", &format!("{n:03}"))
                .unwrap()
                .unwrap()
                .usage_consumed,
            n % 3 == 0
        );
    }
}

#[test]
fn savepoint_and_transaction_rollback_restore_records_index_root_and_audit() {
    let f = Fixture::new();
    f.store.insert(&object("original")).unwrap();
    let before: i64 = f
        .sql()
        .query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))
        .unwrap();
    f.store.begin().unwrap();
    let competing = f.sql();
    competing
        .busy_timeout(std::time::Duration::from_millis(1))
        .unwrap();
    f.store.insert(&object("kept")).unwrap();
    // Public batch code uses the same SQLite savepoint semantics.
    // A second connection cannot write through the immediate transaction.
    assert!(competing.execute("DELETE FROM object_state", []).is_err());
    f.store.rollback().unwrap();
    assert!(f.store.get("alice", "kept").unwrap().is_none());
    f.store.verify_integrity().unwrap();
    assert_eq!(
        f.sql()
            .query_row("SELECT COUNT(*) FROM audit", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before
    );
    f.store.begin().unwrap();
    f.store.insert(&object("committed")).unwrap();
    f.store.commit().unwrap();
    f.store.verify_integrity().unwrap();
    assert!(f.store.get("alice", "committed").unwrap().is_some());
}

#[test]
fn genuine_schema_17_migration_keeps_v1_history_and_binds_existing_state() {
    let mut f = Fixture::new();
    drop(f.store);
    let value = serde_json::to_value(object("legacy")).unwrap();
    legacy::write(&f.path, &f.key, &[value], 17);
    let old: Vec<u8> = Connection::open(&f.path)
        .unwrap()
        .query_row("SELECT mac FROM audit", [], |r| r.get(0))
        .unwrap();
    f.store = Store::open(&f.path, &f.key).unwrap();
    f.store.verify_integrity().unwrap();
    assert_eq!(
        f.sql()
            .query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        STORAGE_SCHEMA as u32
    );
    assert_eq!(
        f.sql()
            .query_row("SELECT mac FROM audit WHERE seq=1", [], |r| r
                .get::<_, Vec<u8>>(0))
            .unwrap(),
        old
    );
    let (principal, root): (String, Vec<u8>) = f
        .sql()
        .query_row(
            "SELECT principal,state_root FROM audit WHERE seq=2",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(principal, "keytend-kmip-server/storage-migration");
    assert_eq!(root.len(), 32);
    assert_eq!(
        f.store.get("alice", "legacy").unwrap().unwrap().material,
        vec![42; 32]
    );
    let backup = f.dir.path().join("backup.sqlite");
    f.store.backup(&backup).unwrap();
    Store::open(&backup, &f.key)
        .unwrap()
        .verify_integrity()
        .unwrap();
}

#[test]
fn corrupted_legacy_migration_rolls_back_schema_and_index_creation() {
    let f = Fixture::new();
    drop(f.store);
    legacy::write(
        &f.path,
        &f.key,
        &[serde_json::to_value(object("legacy")).unwrap()],
        17,
    );
    let sql = Connection::open(&f.path).unwrap();
    sql.execute("UPDATE objects SET sealed=randomblob(80)", [])
        .unwrap();
    assert!(Store::open(&f.path, &f.key).is_err());
    assert_eq!(
        sql.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        17
    );
    assert_eq!(
        sql.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name='object_state'",
            [],
            |r| r.get::<_, u32>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        sql.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('audit') WHERE name='state_root'",
            [],
            |r| r.get::<_, u32>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn backup_refuses_overwrite_and_sidecars() {
    let f = Fixture::new();
    f.store.insert(&object("key")).unwrap();
    let backup = f.dir.path().join("backup.sqlite");
    f.store.backup(&backup).unwrap();
    let before = std::fs::read(&backup).unwrap();
    assert!(f.store.backup(&backup).is_err());
    assert_eq!(std::fs::read(&backup).unwrap(), before);
    let blocked = f.dir.path().join("blocked.sqlite");
    std::fs::write(f.dir.path().join("blocked.sqlite-wal"), b"retained").unwrap();
    assert!(f.store.backup(&blocked).is_err());
    assert!(!blocked.exists());
}
