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

use rusqlite::Connection;
#[path = "support/legacy.rs"]
mod legacy;
use keytend_kmip_server::{
    store::{Object, Store},
    tags::*,
    ttlv::Node,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct Fixture {
    dir: tempfile::TempDir,
    database: PathBuf,
    old_key: PathBuf,
    new_key: PathBuf,
    store: Store,
}
fn key(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn object(id: &str, owner: &str, material: Vec<u8>) -> Object {
    serde_json::from_value(serde_json::json!({
        "id":id, "owner":owner, "object_type":2, "format":1, "algorithm":3,
        "bits":256, "usage":12, "state":2, "material":material,
        "attrs":[Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            Node::structure(USAGE_LIMITS, vec![Node::long(USAGE_LIMITS_TOTAL, 8), Node::long(USAGE_LIMITS_COUNT, 3), Node::enumeration(USAGE_LIMITS_UNIT, 2)])],
        "attribute_indices":{}, "usage_consumed":true,
        "replacement_id":"retained-history", "created":1234, "updated":5678,
        "metadata":{"version":[2,1], "origin":"Generated", "fresh":false, "always_sensitive":false, "never_extractable":false}
    })).unwrap()
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("source.sqlite");
        let old_key = dir.path().join("old.key");
        let new_key = dir.path().join("new.key");
        key(&old_key, &[0x31; 32]);
        key(&new_key, &[0x57; 32]);
        let store = Store::open(&database, &old_key).unwrap();
        Self {
            dir,
            database,
            old_key,
            new_key,
            store,
        }
    }
    fn output(&self) -> PathBuf {
        self.dir.path().join("rotated.sqlite")
    }
    fn sql(&self) -> Connection {
        Connection::open(&self.database).unwrap()
    }
    fn assert_no_output(&self) {
        assert!(!self.output().exists());
        assert!(std::fs::read_dir(self.dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".keytend-kmip-server-rotate-")
        }));
        self.store.verify_audit().unwrap();
    }
}
fn audit_rows(path: &Path) -> Vec<(i64, i64, String, u32, Option<String>, u32)> {
    Connection::open(path)
        .unwrap()
        .prepare(
            "SELECT seq,timestamp,principal,operation,object_id,status FROM audit ORDER BY seq",
        )
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn ciphertexts(path: &Path) -> Vec<Vec<u8>> {
    Connection::open(path)
        .unwrap()
        .prepare("SELECT sealed FROM objects ORDER BY rowid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn rotation_preserves_tenants_history_budgets_and_both_generations_of_backups() {
    let f = Fixture::new();
    for (id, owner) in [("a", "alice"), ("b", "bob"), ("c", "alice")] {
        let mut o = object(id, owner, vec![id.as_bytes()[0]; 32]);
        if id == "c" {
            o.state = 5;
            o.material.clear();
        }
        f.store.insert(&o).unwrap();
        f.store.audit(owner, 1, Some(id), 0).unwrap();
        f.store.audit(owner, 10, Some(id), 1).unwrap();
    }
    let before = ciphertexts(&f.database);
    let old_backup = f.dir.path().join("old-backup.sqlite");
    f.store.backup(&old_backup).unwrap();
    let summary = f.store.rotate_master_key(&f.new_key, &f.output()).unwrap();
    assert_eq!((summary.objects, summary.audit_entries), (3, 10));
    assert_eq!(ciphertexts(&f.database), before);
    assert_eq!(audit_rows(&f.database), audit_rows(&f.output())[..9]);
    assert_eq!(
        audit_rows(&f.output()).last().unwrap().2,
        "keytend-kmip-server/storage-rotation"
    );
    let after = ciphertexts(&f.output());
    assert!(before.iter().zip(&after).all(|(a, b)| a != b));
    let bytes = std::fs::read(f.output()).unwrap();
    for value in before.iter().chain([vec![b'a'; 32], vec![b'b'; 32]].iter()) {
        assert!(!bytes.windows(value.len()).any(|part| part == value));
    }
    assert!(Store::open(&f.output(), &f.old_key).is_err());
    assert!(Store::open(&f.database, &f.new_key).is_err());
    let rotated = Store::open(&f.output(), &f.new_key).unwrap();
    rotated.verify_integrity().unwrap();
    for owner in ["alice", "bob"] {
        let original = f.store.list(owner).unwrap();
        let copied = rotated.list(owner).unwrap();
        assert_eq!(
            serde_json::to_value(original).unwrap(),
            serde_json::to_value(copied).unwrap()
        );
    }
    assert!(rotated.get("alice", "b").unwrap().is_none());
    rotated.audit("alice", 24, None, 0).unwrap();
    rotated.verify_audit().unwrap();
    let backup = f.dir.path().join("new-backup.sqlite");
    rotated.backup(&backup).unwrap();
    Store::open(&backup, &f.new_key)
        .unwrap()
        .verify_integrity()
        .unwrap();
    Store::open(&old_backup, &f.old_key)
        .unwrap()
        .verify_integrity()
        .unwrap();
    assert!(Store::open(&old_backup, &f.new_key).is_err());
    let third = f.dir.path().join("third.key");
    key(&third, &[0x83; 32]);
    let twice = f.dir.path().join("twice.sqlite");
    assert_eq!(
        rotated
            .rotate_master_key(&third, &twice)
            .unwrap()
            .audit_entries,
        12
    );
    Store::open(&twice, &third)
        .unwrap()
        .verify_integrity()
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(f.output()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn empty_store_rotates_and_rejects_same_key_bytes_not_just_same_path() {
    let f = Fixture::new();
    key(&f.new_key, &[0x31; 32]);
    assert!(f.store.rotate_master_key(&f.new_key, &f.output()).is_err());
    f.assert_no_output();
    key(&f.new_key, &[0x57; 32]);
    let summary = f.store.rotate_master_key(&f.new_key, &f.output()).unwrap();
    assert_eq!((summary.objects, summary.audit_entries), (0, 1));
    Store::open(&f.output(), &f.new_key)
        .unwrap()
        .verify_integrity()
        .unwrap();
    assert!(Store::open(&f.output(), &f.old_key).is_err());
}

#[test]
fn invalid_new_keys_and_output_collisions_never_modify_the_source() {
    let f = Fixture::new();
    for length in [0, 31, 33, 64] {
        key(&f.new_key, &vec![1; length]);
        assert!(f.store.rotate_master_key(&f.new_key, &f.output()).is_err());
        f.assert_no_output();
    }
    key(&f.new_key, &[0x57; 32]);
    assert!(f.store.rotate_master_key(&f.new_key, &f.database).is_err());
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let name = PathBuf::from(format!("{}{suffix}", f.output().display()));
        std::fs::write(&name, b"do not overwrite").unwrap();
        assert!(f.store.rotate_master_key(&f.new_key, &f.output()).is_err());
        assert_eq!(std::fs::read(&name).unwrap(), b"do not overwrite");
        std::fs::remove_file(name).unwrap();
        f.assert_no_output();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        std::fs::set_permissions(&f.new_key, std::fs::Permissions::from_mode(0o604)).unwrap();
        assert!(f.store.rotate_master_key(&f.new_key, &f.output()).is_err());
        f.assert_no_output();
        key(&f.new_key, &[0x57; 32]);
        symlink(f.dir.path().join("missing"), f.output()).unwrap();
        assert!(f.store.rotate_master_key(&f.new_key, &f.output()).is_err());
        assert!(
            std::fs::symlink_metadata(f.output())
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}

#[test]
fn corrupted_object_or_unknown_metadata_cannot_be_published() {
    for corruption in ["ciphertext", "identity", "metadata", "schema"] {
        let f = Fixture::new();
        f.store
            .insert(&object("good", "alice", vec![1; 32]))
            .unwrap();
        f.store.insert(&object("bad", "bob", vec![2; 32])).unwrap();
        f.store.audit("alice", 1, Some("good"), 0).unwrap();
        match corruption {
            "ciphertext" => {
                f.sql()
                    .execute(
                        "UPDATE objects SET sealed=zeroblob(length(sealed)) WHERE id='bad'",
                        [],
                    )
                    .unwrap();
            }
            "identity" => {
                f.sql()
                    .execute("UPDATE objects SET owner='mallory' WHERE id='bad'", [])
                    .unwrap();
            }
            "schema" => {
                f.sql().execute_batch("PRAGMA user_version=19").unwrap();
            }
            _ => {
                f.sql()
                    .execute("INSERT INTO meta VALUES('unknown',x'01')", [])
                    .unwrap();
            }
        }
        let original = ciphertexts(&f.database);
        assert!(f.store.rotate_master_key(&f.new_key, &f.output()).is_err());
        assert_eq!(original, ciphertexts(&f.database));
        f.assert_no_output();
        assert_eq!(
            f.store.get("alice", "good").unwrap().unwrap().material,
            vec![1; 32]
        );
        if ["ciphertext", "identity"].contains(&corruption) {
            assert!(f.store.verify_integrity().is_err());
        }
    }
}

#[test]
fn audit_corruption_is_checked_again_inside_the_copy_snapshot() {
    let f = Fixture::new();
    f.store.audit("alice", 1, None, 0).unwrap();
    f.sql().execute("UPDATE audit SET status=1", []).unwrap();
    assert!(f.store.rotate_master_key(&f.new_key, &f.output()).is_err());
    assert!(!f.output().exists());
    assert!(f.store.verify_integrity().is_err());
}

#[test]
fn concurrent_writer_cannot_mix_object_and_audit_snapshots() {
    let f = Fixture::new();
    for n in 0..24 {
        f.store
            .insert(&object(&n.to_string(), "alice", vec![0; 32]))
            .unwrap();
    }
    f.store.audit("alice", 1, Some("0"), 0).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let writer_stop = stop.clone();
    let db = f.database.clone();
    let old = f.old_key.clone();
    let writer = std::thread::spawn(move || {
        let store = Store::open(&db, &old).unwrap();
        for epoch in 1..=200u8 {
            if writer_stop.load(Ordering::SeqCst) {
                break;
            }
            store.begin().unwrap();
            for n in 0..24 {
                let mut o = store.get("alice", &n.to_string()).unwrap().unwrap();
                o.material = vec![epoch; 32];
                store.put(&o).unwrap();
            }
            store
                .audit("alice", 1, Some(&epoch.to_string()), 0)
                .unwrap();
            store.commit().unwrap();
        }
    });
    let result = f.store.rotate_master_key(&f.new_key, &f.output());
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    result.unwrap();
    let rotated = Store::open(&f.output(), &f.new_key).unwrap();
    let rows = audit_rows(&f.output());
    let epoch: u8 = rows
        .iter()
        .rev()
        .find(|row| row.2 == "alice")
        .unwrap()
        .4
        .as_ref()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        rotated
            .list("alice")
            .unwrap()
            .iter()
            .all(|o| o.material == vec![epoch; 32])
    );
    rotated.verify_integrity().unwrap();
}

#[test]
fn unknown_serialized_object_fields_are_preserved_exactly() {
    // A genuine legacy record may contain fields unknown to this binary.
    use openssl::symm::Cipher;
    let mut f = Fixture::new();
    let mut value = serde_json::to_value(object("extension", "alice", vec![0x71; 32])).unwrap();
    value["future_field"] = serde_json::json!({"nested":[1,2,3]});
    let plaintext = serde_json::to_vec(&value).unwrap();
    drop(f.store);
    legacy::write(&f.database, &f.old_key, &[value], 17);
    f.store = Store::open(&f.database, &f.old_key).unwrap();
    f.store.rotate_master_key(&f.new_key, &f.output()).unwrap();
    let ciphertext = &ciphertexts(&f.output())[0];
    let decrypted = openssl::symm::decrypt_aead(
        Cipher::aes_256_gcm(),
        &[0x57; 32],
        Some(&ciphertext[1..13]),
        b"keytend-kmip-server object v1\0alice\0extension",
        &ciphertext[29..],
        &ciphertext[13..29],
    )
    .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn interrupted_cli_rotation_leaves_source_usable_and_can_be_retried() {
    let f = Fixture::new();
    for n in 0..48 {
        f.store
            .insert(&object(&n.to_string(), "alice", vec![0xa7; 65536]))
            .unwrap();
        f.store.audit("alice", 1, Some(&n.to_string()), 0).unwrap();
    }
    let before = ciphertexts(&f.database);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_keytend-kmip-server"))
        .arg("rotate-master-key")
        .arg("--database")
        .arg(&f.database)
        .arg("--master-key")
        .arg(&f.old_key)
        .arg("--new-master-key")
        .arg(&f.new_key)
        .arg("--output")
        .arg(f.output())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let writing = std::fs::read_dir(f.dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".keytend-kmip-server-rotate-")
            })
            .any(|entry| {
                std::fs::metadata(entry.path().join("kmip.sqlite-wal"))
                    .is_ok_and(|m| m.len() > 1024 * 1024)
            });
        if writing {
            child.kill().unwrap();
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "rotation completed before interruption test could observe copying"
        );
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("rotation did not begin copying");
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(!child.wait().unwrap().success());
    assert!(!f.output().exists());
    assert_eq!(before, ciphertexts(&f.database));
    f.store.verify_integrity().unwrap();
    f.store.rotate_master_key(&f.new_key, &f.output()).unwrap();
    Store::open(&f.output(), &f.new_key)
        .unwrap()
        .verify_integrity()
        .unwrap();
}
