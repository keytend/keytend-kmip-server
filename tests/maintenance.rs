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

//! Shell-free maintenance commands: read-only `check-store`, `backup` and
//! `audit-checkpoint` (also on older schemas), the writer lock against a
//! running `serve`, directory backups with retention, `restore`, and
//! in-place master-key rotation, its revert and their crash recovery.
#[path = "support/legacy.rs"]
mod legacy;
use keytend_kmip_server::store::{Object, STORAGE_SCHEMA, Store, WriterLock};
use rusqlite::Connection;
use std::{
    fs,
    io::{BufRead, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const BIN: &str = env!("CARGO_BIN_EXE_keytend-kmip-server");

fn key(path: &Path, byte: u8) {
    fs::write(path, [byte; 32]).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn object(id: &str) -> Object {
    serde_json::from_value(serde_json::json!({
        "id": id, "owner": "alice", "object_type": 2, "format": 1, "algorithm": 3,
        "bits": 256, "usage": 12, "state": 2, "material": vec![7u8; 32], "attrs": [],
        "created": 1234, "updated": 5678
    }))
    .unwrap()
}
fn add(database: &Path, master_key: &Path, ids: &[&str]) {
    let store = Store::open(database, master_key).unwrap();
    for id in ids {
        store.insert(&object(id)).unwrap();
        store.audit("alice", 1, Some(id), 0).unwrap();
    }
}
fn objects(database: &Path, master_key: &Path) -> u64 {
    Store::open_read_only(database, master_key)
        .unwrap()
        .verify()
        .unwrap()
        .objects
}
fn cli(args: &[&dyn AsRef<std::ffi::OsStr>]) -> Output {
    Command::new(BIN)
        .args(args.iter().map(|a| a.as_ref()))
        .output()
        .unwrap()
}
fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}
fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
fn ok(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        stdout(&output),
        stderr(&output)
    );
    stdout(&output)
}
fn fails(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        stdout(&output),
        stderr(&output)
    );
    stderr(&output)
}
fn schema(path: &Path) -> i32 {
    Connection::open(path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}
/// Wait until this process's dropped lock is really free: a child that
/// another test forks at that moment briefly shares the open lock (flock
/// belongs to the open file) until it executes.
fn released(database: &Path) {
    for _ in 0..500 {
        if WriterLock::acquire(database, "test").is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("the writer lock of {} was not released", database.display());
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

struct Fixture {
    dir: tempfile::TempDir,
    data: PathBuf,
    database: PathBuf,
    old_key: PathBuf,
    new_key: PathBuf,
    other_key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        let database = data.join("kmip.sqlite");
        let old_key = dir.path().join("old.key");
        let new_key = dir.path().join("new.key");
        let other_key = dir.path().join("other.key");
        key(&old_key, 0x31);
        key(&new_key, 0x57);
        key(&other_key, 0x99);
        Self {
            dir,
            data,
            database,
            old_key,
            new_key,
            other_key,
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn rotate(&self, extra: &[&dyn AsRef<std::ffi::OsStr>]) -> Output {
        let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
            &"rotate-master-key",
            &"--in-place",
            &"--database",
            &self.database,
            &"--master-key",
            &self.new_key,
            &"--previous-master-key",
            &self.old_key,
        ];
        args.extend_from_slice(extra);
        cli(&args)
    }
    fn restore(
        &self,
        from: &Path,
        id: &str,
        master_key: &Path,
        extra: &[&dyn AsRef<std::ffi::OsStr>],
    ) -> Output {
        let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
            &"restore",
            &"--from",
            &from,
            &"--id",
            &id,
            &"--database",
            &self.database,
            &"--master-key",
            &master_key,
        ];
        args.extend_from_slice(extra);
        cli(&args)
    }
    fn pre_rotation(&self) -> Vec<PathBuf> {
        names(&self.data)
            .into_iter()
            .filter(|n| n.starts_with("pre-rotation-"))
            .map(|n| self.data.join(n))
            .collect()
    }
}

#[test]
fn older_schema_store_is_verified_backed_up_and_checkpointed_without_migration() {
    let f = Fixture::new();
    let values: Vec<_> = ["a", "b"]
        .iter()
        .map(|id| serde_json::to_value(object(id)).unwrap())
        .collect();
    legacy::write(&f.database, &f.old_key, &values, 17);
    let before = fs::read(&f.database).unwrap();
    let out = ok(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    assert!(out.starts_with("Master key, object records and audit chain verified\n"));
    assert!(
        out.contains("Storage schema 17 is older than this release's 18"),
        "{out}"
    );
    let backup = f.path("legacy-backup.sqlite");
    let backup_run = cli(&[
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output",
        &backup,
    ]);
    assert!(stderr(&backup_run).contains("Storage schema 17"));
    ok(backup_run);
    let dir = f.path("backups");
    fs::create_dir(&dir).unwrap();
    ok(cli(&[
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &dir,
    ]));
    let checkpoint = f.path("legacy-checkpoint.json");
    ok(cli(&[
        &"audit-checkpoint",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output",
        &checkpoint,
    ]));
    ok(cli(&[
        &"check-store",
        &"--database",
        &backup,
        &"--master-key",
        &f.old_key,
        &"--audit-checkpoint",
        &checkpoint,
    ]));
    // Nothing above changed or upgraded the source, and the copies are
    // copies of the store as it is.
    assert_eq!(fs::read(&f.database).unwrap(), before);
    assert_eq!(schema(&f.database), 17);
    assert!(!sidecar(&f.database, "-wal").exists());
    assert_eq!(schema(&backup), 17);
    let verification = Store::open_read_only(&backup, &f.old_key)
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(
        (
            verification.storage_schema,
            verification.objects,
            verification.object_index_verified
        ),
        (17, 2, false)
    );
    let latest: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("latest.json")).unwrap()).unwrap();
    assert_eq!(latest["verification"]["storage_schema"], 17);
    assert_eq!(latest["verification"]["object_index_verified"], false);
    // The checkpoint of the older store still verifies once the server
    // has upgraded it.
    let upgraded = Store::open(&backup, &f.old_key).unwrap();
    upgraded.verify_audit_checkpoint(&checkpoint).unwrap();
    assert_eq!(schema(&backup), STORAGE_SCHEMA);
    // Read-only verification still authenticates every older record.
    Connection::open(&f.database)
        .unwrap()
        .execute(
            "UPDATE objects SET sealed=CAST(x'01'||randomblob(79) AS BLOB) WHERE id='b'",
            [],
        )
        .unwrap();
    let error = fails(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    assert!(error.contains("record authentication failed"), "{error}");
    assert_eq!(schema(&f.database), 17);
}

#[test]
fn read_only_commands_leave_a_current_store_unchanged_and_refuse_newer_ones() {
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a", "b", "c"]);
    let before = fs::read(&f.database).unwrap();
    // A writer stays open while the read-only commands run.
    let live = Store::open(&f.database, &f.old_key).unwrap();
    ok(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    let backup = f.path("b.sqlite");
    ok(cli(&[
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output",
        &backup,
    ]));
    ok(cli(&[
        &"audit-checkpoint",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output",
        &f.path("cp.json"),
    ]));
    live.insert(&object("d")).unwrap();
    drop(live);
    assert_eq!(objects(&backup, &f.old_key), 3);
    assert!(!sidecar(&backup, "-wal").exists() && !sidecar(&backup, "-shm").exists());
    assert_ne!(
        fs::read(&f.database).unwrap(),
        before,
        "the writer's change is kept"
    );
    let copy = fs::read(&f.database).unwrap();
    ok(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    assert_eq!(fs::read(&f.database).unwrap(), copy);
    // A wrong key or a newer schema fails without a change.
    let error = fails(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.other_key,
    ]));
    assert!(error.contains("record authentication failed"), "{error}");
    Connection::open(&f.database)
        .unwrap()
        .execute_batch(&format!("PRAGMA user_version={}", STORAGE_SCHEMA + 1))
        .unwrap();
    let error = fails(cli(&[
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output",
        &f.path("n.sqlite"),
    ]));
    assert!(
        error.contains("database schema is newer than this binary"),
        "{error}"
    );
    assert!(!f.path("n.sqlite").exists());
}

#[test]
fn read_only_directory_falls_back_to_an_immutable_read_unless_the_server_holds_the_lock() {
    let f = Fixture::new();
    if std::os::unix::fs::MetadataExt::uid(&fs::metadata(&f.data).unwrap()) == 0 {
        return; // root ignores directory permissions
    }
    add(&f.database, &f.old_key, &["a"]);
    drop(WriterLock::acquire(&f.database, "serve").unwrap());
    released(&f.database);
    assert!(!sidecar(&f.database, "-wal").exists());
    fs::set_permissions(&f.data, fs::Permissions::from_mode(0o500)).unwrap();
    let check = || {
        cli(&[
            &"check-store",
            &"--database",
            &f.database,
            &"--master-key",
            &f.old_key,
        ])
    };
    ok(check());
    let backup = f.path("ro.sqlite");
    let run = cli(&[
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output",
        &backup,
    ]);
    assert!(
        stderr(&run).contains("the backup time was not recorded"),
        "{}",
        stderr(&run)
    );
    ok(run);
    assert_eq!(objects(&backup, &f.old_key), 1);
    // The lock is still openable read-only; while another process holds it
    // exclusively, the immutable read is refused.
    fs::set_permissions(&f.data, fs::Permissions::from_mode(0o700)).unwrap();
    let held = WriterLock::acquire(&f.database, "serve").unwrap();
    fs::set_permissions(&f.data, fs::Permissions::from_mode(0o500)).unwrap();
    let error = fails(check());
    assert!(
        error.contains("the store is in use by a running server"),
        "{error}"
    );
    drop(held);
    released(&f.database);
    ok(check());
    fs::set_permissions(&f.data, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn directory_backups_are_verified_pruned_and_described_in_latest_json() {
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a", "b"]);
    let dir = f.path("backups");
    fs::create_dir(&dir).unwrap();
    // Three earlier backups of this database, written by the command; the
    // decoys (including look-alike copies) are not removed.
    let mut earlier = vec![];
    for _ in 0..3 {
        ok(backup_into(&f, &dir, "10"));
        let latest: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("latest.json")).unwrap()).unwrap();
        earlier.push(latest["file"].as_str().unwrap().to_string());
        next_second();
    }
    fs::copy(dir.join(&earlier[0]), dir.join("backup-manual.sqlite")).unwrap();
    fs::copy(
        dir.join(&earlier[0]),
        dir.join("backup-20200101T000000Z.sqlite"),
    )
    .unwrap();
    for name in ["backup-20230101T000000Z.sqlite-wal", "notes.txt"] {
        fs::write(dir.join(name), b"x").unwrap();
    }
    fs::create_dir(dir.join("backup-20190101T000000Z.sqlite")).unwrap();
    let out = ok(cli(&[
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &dir,
        &"--retain",
        &"2",
    ]));
    assert!(out.contains("written and verified: 2 objects"), "{out}");
    assert!(out.contains("Removed 2 older backups"), "{out}");
    assert!(out.contains("not recorded as backups of"), "{out}");
    let latest: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("latest.json")).unwrap()).unwrap();
    let file = latest["file"].as_str().unwrap().to_string();
    assert!(file.starts_with("backup-") && file.ends_with("Z.sqlite"));
    assert_eq!(latest["verified"], true);
    assert_eq!(latest["verification"]["objects"], 2);
    assert_eq!(
        latest["bytes"],
        fs::metadata(dir.join(&file)).unwrap().len()
    );
    assert_eq!(
        latest["pruned"],
        serde_json::json!([earlier[0], earlier[1]])
    );
    let mut expected = vec![
        ".backup.lock".to_string(),
        "backup-20190101T000000Z.sqlite".into(),
        "backup-20200101T000000Z.sqlite".into(),
        "backup-20230101T000000Z.sqlite-wal".into(),
        earlier[2].clone(),
        file.clone(),
        "backup-index.json".into(),
        "backup-manual.sqlite".into(),
        "latest.json".into(),
        "notes.txt".into(),
    ];
    expected.sort();
    assert_eq!(names(&dir), expected);
    assert_eq!(
        fs::metadata(dir.join(&file)).unwrap().permissions().mode() & 0o777,
        0o400
    );
    ok(cli(&[
        &"check-store",
        &"--database",
        &dir.join(&file),
        &"--master-key",
        &f.old_key,
    ]));
    let recorded: i64 = fs::read_to_string(sidecar(&f.database, ".last-backup"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(recorded, latest["created_unix"].as_i64().unwrap());
    // Usage errors exit 2.
    for args in [
        vec!["--output", "x", "--output-dir", "y"],
        vec!["--output-dir", "y", "--retain", "0"],
        vec!["--output", "x", "--retain", "1"],
        vec![],
    ] {
        let mut all: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
            &"backup",
            &"--database",
            &f.database,
            &"--master-key",
            &f.old_key,
        ];
        all.extend(args.iter().map(|a| a as &dyn AsRef<std::ffi::OsStr>));
        assert_eq!(cli(&all).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn restore_installs_a_verified_copy_keeps_the_previous_database_and_is_idempotent() {
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a", "b"]);
    let backup = f.path("backup.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    add(&f.database, &f.old_key, &["c"]);
    let out = ok(f.restore(&backup, "r1", &f.old_key, &[]));
    assert!(out.contains("Verified backup"), "{out}");
    assert!(out.contains("the previous database is in"), "{out}");
    assert_eq!(objects(&f.database, &f.old_key), 2);
    let previous = f.data.join("pre-restore-r1");
    assert_eq!(objects(&previous.join("kmip.sqlite"), &f.old_key), 3);
    assert_eq!(
        fs::metadata(&f.database).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let marker: serde_json::Value =
        serde_json::from_slice(&fs::read(f.data.join(".restore-r1")).unwrap()).unwrap();
    assert_eq!(marker["id"], "r1");
    assert!(!f.data.join(".restore-r1.sqlite.tmp").exists());
    // The server writes after the restore; the same id changes nothing, even
    // when the backup is gone.
    add(&f.database, &f.old_key, &["d"]);
    fs::remove_file(&backup).unwrap();
    let out = ok(f.restore(&backup, "r1", &f.old_key, &[]));
    assert!(out.contains("Restore r1 already completed"), "{out}");
    assert_eq!(objects(&f.database, &f.old_key), 3);
    // Recovery onto an empty volume: no database yet.
    let g = Fixture::new();
    let copy = g.path("copy.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&copy)
        .unwrap();
    let out = ok(g.restore(&copy, "new-cluster", &f.old_key, &[]));
    assert!(out.contains("there was no database before"), "{out}");
    assert_eq!(objects(&g.database, &f.old_key), 3);
    Store::open(&g.database, &f.old_key).unwrap();
}

#[test]
fn restore_refuses_a_wrong_key_a_bad_backup_an_old_checkpoint_and_an_interrupted_run() {
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let backup = f.path("backup.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    add(&f.database, &f.old_key, &["b"]);
    let checkpoint = f.path("cp.json");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .write_audit_checkpoint(&checkpoint, None)
        .unwrap();
    let before = names(&f.data);
    let content = fs::read(&f.database).unwrap();
    let unchanged = || {
        assert_eq!(names(&f.data), before);
        assert_eq!(fs::read(&f.database).unwrap(), content);
    };
    let error = fails(f.restore(&backup, "r", &f.other_key, &[]));
    assert!(error.contains("record authentication failed"), "{error}");
    unchanged();
    let error = fails(f.restore(
        &backup,
        "r",
        &f.old_key,
        &[&"--audit-checkpoint", &checkpoint],
    ));
    assert!(
        error.contains("older than or diverges from the required checkpoint"),
        "{error}"
    );
    unchanged();
    let corrupt = f.path("corrupt.sqlite");
    fs::copy(&backup, &corrupt).unwrap();
    Connection::open(&corrupt)
        .unwrap()
        .execute("UPDATE objects SET sealed=randomblob(80)", [])
        .unwrap();
    fails(f.restore(&corrupt, "r", &f.old_key, &[]));
    unchanged();
    let error = fails(f.restore(&f.database, "r", &f.old_key, &[]));
    assert!(error.contains("--from is the database itself"), "{error}");
    assert_eq!(
        f.restore(&backup, "../x", &f.old_key, &[]).status.code(),
        Some(1)
    );
    unchanged();
    // A directory of that name that restore did not make is not reused.
    fs::create_dir(f.data.join("pre-restore-r9")).unwrap();
    let error = fails(f.restore(&backup, "r9", &f.old_key, &[]));
    assert!(error.contains("was not made by restore r9"), "{error}");
    assert_eq!(fs::read(&f.database).unwrap(), content);
    // A valid restore against a checkpoint the backup satisfies.
    let older = f.path("older.json");
    Store::open_read_only(&backup, &f.old_key)
        .unwrap()
        .write_audit_checkpoint(&older, None)
        .unwrap();
    ok(f.restore(&backup, "r", &f.old_key, &[&"--audit-checkpoint", &older]));
    assert_eq!(objects(&f.database, &f.old_key), 1);
}

struct Server {
    child: std::process::Child,
    health: std::net::SocketAddr,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn certificates(dir: &Path) -> String {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::{PKey, Private},
        rsa::Rsa,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName},
        },
    };
    let issue = |name: &str, issuer: Option<&(X509, PKey<Private>)>, usage: &str| {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(
            &BigNum::from_u32(rand_serial())
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
        b.set_subject_name(&subject).unwrap();
        b.set_issuer_name(issuer.map_or(&subject, |i| i.0.subject_name()))
            .unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        match usage {
            "ca" => b
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap(),
            "server" => {
                let san = SubjectAlternativeName::new()
                    .dns("localhost")
                    .build(&b.x509v3_context(issuer.map(|i| &*i.0), None))
                    .unwrap();
                b.append_extension(san).unwrap();
                b.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
                    .unwrap();
            }
            _ => b
                .append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
                .unwrap(),
        }
        b.sign(issuer.map_or(&key, |i| &i.1), MessageDigest::sha256())
            .unwrap();
        (b.build(), key)
    };
    fn rand_serial() -> u32 {
        let mut bytes = [0; 4];
        openssl::rand::rand_bytes(&mut bytes).unwrap();
        u32::from_be_bytes(bytes) >> 1
    }
    let ca = issue("test ca", None, "ca");
    let server = issue("localhost", Some(&ca), "server");
    let client = issue("client", Some(&ca), "client");
    fs::write(dir.join("ca.pem"), ca.0.to_pem().unwrap()).unwrap();
    fs::write(dir.join("server.pem"), server.0.to_pem().unwrap()).unwrap();
    fs::write(
        dir.join("server.key"),
        server.1.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    fs::set_permissions(dir.join("server.key"), fs::Permissions::from_mode(0o600)).unwrap();
    hex::encode(client.0.digest(MessageDigest::sha256()).unwrap())
}
fn free_port() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn serve(f: &Fixture, master_key: &Path) -> Result<Server, String> {
    let fingerprint = certificates(f.dir.path());
    fs::write(
        f.path("policy.json"),
        serde_json::json!({"principals": {fingerprint: {"name": "alice", "operations": [1]}}})
            .to_string(),
    )
    .unwrap();
    let health = free_port();
    let mut child = Command::new(BIN)
        .args(["serve", "--listen", "127.0.0.1:0", "--health-listen"])
        .arg(health.to_string())
        .arg("--cert")
        .arg(f.path("server.pem"))
        .arg("--key")
        .arg(f.path("server.key"))
        .arg("--ca")
        .arg(f.path("ca.pem"))
        .arg("--policy")
        .arg(f.path("policy.json"))
        .arg("--database")
        .arg(&f.database)
        .arg("--master-key")
        .arg(master_key)
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
    for line in lines.by_ref() {
        let line = line.unwrap();
        if line.contains("KMIP listener ready") {
            std::thread::spawn(move || for _ in lines {});
            return Ok(Server { child, health });
        }
    }
    let mut error = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();
    child.wait().unwrap();
    Err(error)
}
fn metric(health: std::net::SocketAddr, name: &str) -> f64 {
    let mut s = std::net::TcpStream::connect(health).unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut body = String::new();
    s.read_to_string(&mut body).unwrap();
    body.lines()
        .find_map(|l| l.strip_prefix(name).and_then(|v| v.strip_prefix(' ')))
        .unwrap_or_else(|| panic!("{name} missing from {body}"))
        .parse()
        .unwrap()
}

#[test]
fn a_running_server_holds_the_writer_lock_and_reports_the_last_backup() {
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let backup = f.path("backup.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    let server = serve(&f, &f.old_key).unwrap();
    assert_eq!(
        metric(server.health, "kmip_last_backup_timestamp_seconds"),
        0.0
    );
    let lock = fs::read_to_string(sidecar(&f.database, ".lock")).unwrap();
    assert!(lock.starts_with("serve (pid "), "{lock}");
    for error in [
        fails(f.restore(&backup, "r1", &f.old_key, &[])),
        fails(f.rotate(&[])),
        fails(f.rotate(&[&"--revert"])),
    ] {
        assert!(
            error.contains("the store is in use by a running server (lock ")
                && error.contains("held by serve"),
            "{error}"
        );
    }
    assert!(!f.data.join("pre-restore-r1").exists());
    assert!(f.pre_rotation().is_empty());
    let second = serve(&f, &f.old_key)
        .err()
        .expect("a second server started");
    assert!(
        second.contains("the store is in use by a running server"),
        "{second}"
    );
    // Online backups and checks take no lock.
    let dir = f.path("backups");
    fs::create_dir(&dir).unwrap();
    ok(cli(&[
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &dir,
    ]));
    ok(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    let recorded: f64 = fs::read_to_string(sidecar(&f.database, ".last-backup"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(recorded > 1.7e9);
    assert_eq!(
        metric(server.health, "kmip_last_backup_timestamp_seconds"),
        recorded
    );
    drop(server);
    ok(f.restore(&backup, "r1", &f.old_key, &[]));
    let server = serve(&f, &f.old_key).unwrap();
    drop(server);
}

#[test]
fn in_place_rotation_rotates_once_then_does_nothing_and_refuses_unknown_keys() {
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a", "b"]);
    let out = ok(f.rotate(&[]));
    assert!(
        out.contains("Verified rotated snapshot: 2 objects"),
        "{out}"
    );
    assert!(out.contains("Rotated "), "{out}");
    assert!(Store::master_key_opens(&f.database, &f.new_key).unwrap());
    assert_eq!(objects(&f.database, &f.new_key), 2);
    let pre = f.pre_rotation();
    assert_eq!(pre.len(), 1);
    assert_eq!(objects(&pre[0].join("kmip.sqlite"), &f.old_key), 2);
    assert!(!sidecar(&f.database, ".rotated").exists());
    assert!(!sidecar(&f.database, ".rotation.json").exists());
    let rotated = fs::read(&f.database).unwrap();
    let out = ok(f.rotate(&[]));
    assert!(
        out.contains("already opens with --master-key; nothing to rotate"),
        "{out}"
    );
    assert_eq!(fs::read(&f.database).unwrap(), rotated);
    // Neither key: refused, nothing changed.
    let error = fails(cli(&[
        &"rotate-master-key",
        &"--in-place",
        &"--database",
        &f.database,
        &"--master-key",
        &f.other_key,
        &"--previous-master-key",
        &f.old_key,
    ]));
    assert!(
        error.contains("neither --master-key nor --previous-master-key opens"),
        "{error}"
    );
    let error = fails(cli(&[
        &"rotate-master-key",
        &"--in-place",
        &"--database",
        &f.database,
        &"--master-key",
        &f.new_key,
        &"--previous-master-key",
        &f.new_key,
    ]));
    assert!(error.contains("hold the same key"), "{error}");
    assert_eq!(fs::read(&f.database).unwrap(), rotated);
    assert_eq!(f.pre_rotation(), pre);
    // Usage errors exit 2.
    for args in [
        vec![
            "rotate-master-key",
            "--in-place",
            "--database",
            "d",
            "--master-key",
            "k",
        ],
        vec![
            "rotate-master-key",
            "--in-place",
            "--previous-master-key",
            "p",
            "--database",
            "d",
            "--master-key",
            "k",
            "--output",
            "o",
        ],
        vec![
            "rotate-master-key",
            "--database",
            "d",
            "--master-key",
            "k",
            "--revert",
        ],
        vec![
            "rotate-master-key",
            "--database",
            "d",
            "--master-key",
            "k",
            "--new-master-key",
            "n",
            "--output",
            "o",
            "--previous-master-key",
            "p",
        ],
    ] {
        let a: Vec<&dyn AsRef<std::ffi::OsStr>> = args
            .iter()
            .map(|a| a as &dyn AsRef<std::ffi::OsStr>)
            .collect();
        assert_eq!(cli(&a).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn in_place_rotation_moves_the_checkpoint_to_the_new_key_generation() {
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let old_checkpoint = f.path("old-cp.json");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .write_audit_checkpoint(&old_checkpoint, None)
        .unwrap();
    let output = f.path("new-cp.json");
    let out = ok(f.rotate(&[
        &"--audit-checkpoint",
        &old_checkpoint,
        &"--checkpoint-output",
        &output,
    ]));
    assert!(
        out.contains("Audit checkpoint for the store's master key written to"),
        "{out}"
    );
    let check = |checkpoint: &Path| {
        cli(&[
            &"check-store",
            &"--database",
            &f.database,
            &"--master-key",
            &f.new_key,
            &"--audit-checkpoint",
            &checkpoint,
        ])
    };
    ok(check(&output));
    fails(check(&old_checkpoint));
    // Every later start can pass the previous generation's checkpoint while
    // the pre-rotation copy is kept: it yields one for the new key.
    let again = f.path("again.json");
    let out = ok(f.rotate(&[
        &"--audit-checkpoint",
        &old_checkpoint,
        &"--checkpoint-output",
        &again,
    ]));
    assert!(out.contains("belongs to the previous master key"), "{out}");
    ok(check(&again));
    let out = ok(f.rotate(&[
        &"--audit-checkpoint",
        &output,
        &"--checkpoint-output",
        &again,
    ]));
    assert!(out.contains("already verifies against the store"), "{out}");
    let error = fails(f.rotate(&[&"--audit-checkpoint", &old_checkpoint]));
    assert!(
        error.contains("belongs to the master key before the rotation"),
        "{error}"
    );
    // A checkpoint that verifies neither generation fails closed.
    add(&f.database, &f.new_key, &["b"]);
    let ahead = f.path("ahead.json");
    Store::open_read_only(&f.database, &f.new_key)
        .unwrap()
        .write_audit_checkpoint(&ahead, None)
        .unwrap();
    let pre = f.pre_rotation().remove(0);
    let saved = fs::read(pre.join("kmip.sqlite")).unwrap();
    let error = fails(f.rotate(&[&"--audit-checkpoint", &f.path("missing.json")]));
    assert!(error.contains("does not verify the store"), "{error}");
    assert_eq!(fs::read(pre.join("kmip.sqlite")).unwrap(), saved);
    ok(f.rotate(&[&"--audit-checkpoint", &ahead]));
}

#[test]
fn revert_puts_back_the_pre_rotation_database_once() {
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let checkpoint = f.path("cp.json");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .write_audit_checkpoint(&checkpoint, None)
        .unwrap();
    ok(f.rotate(&[]));
    add(&f.database, &f.new_key, &["after-rotation"]);
    let pre = f.pre_rotation().remove(0);
    let stamp = pre.file_name().unwrap().to_str().unwrap()["pre-rotation-".len()..].to_string();
    let out = ok(f.rotate(&[&"--revert", &"--audit-checkpoint", &checkpoint]));
    assert!(out.contains("Reverted "), "{out}");
    assert!(Store::master_key_opens(&f.database, &f.old_key).unwrap());
    assert_eq!(objects(&f.database, &f.old_key), 1);
    assert!(!pre.exists());
    let post = f.data.join(format!("post-rotation-{stamp}"));
    assert_eq!(objects(&post.join("kmip.sqlite"), &f.new_key), 2);
    let out = ok(f.rotate(&[&"--revert"]));
    assert!(
        out.contains("already opens with --previous-master-key; nothing to revert"),
        "{out}"
    );
    assert!(!sidecar(&f.database, ".revert.json").exists());
    // With nothing to revert to, a rotated store is refused.
    let g = Fixture::new();
    add(&g.database, &g.new_key, &["x"]);
    let error = fails(g.rotate(&[&"--revert"]));
    assert!(
        error.contains("no pre-rotation copy to revert to"),
        "{error}"
    );
}

/// Leave the state a rotation killed at a given step would leave.
fn rotated_copy(f: &Fixture) -> PathBuf {
    let rotated = sidecar(&f.database, ".rotated");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .rotate_master_key(&f.new_key, &rotated)
        .unwrap();
    rotated
}
fn journal(f: &Fixture, pre: &str) {
    fs::write(
        sidecar(&f.database, ".rotation.json"),
        serde_json::json!({"pre": pre}).to_string(),
    )
    .unwrap();
}
/// Move the database's files from `from` to `to`; `main_only` stops after
/// the main file, as a run killed mid-move would.
fn move_database(from: &Path, to: &Path, main_only: bool) {
    fs::create_dir_all(to).unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let source = from.join(format!("kmip.sqlite{suffix}"));
        if source.exists() {
            fs::rename(&source, to.join(format!("kmip.sqlite{suffix}"))).unwrap();
        }
        if main_only {
            return;
        }
    }
}
const PRE: &str = "pre-rotation-20261105T021500Z";

#[test]
fn interrupted_rotations_resume_or_start_again() {
    // Killed after publishing the copy, before the cutover began: the copy
    // is written again.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    rotated_copy(&f);
    add(&f.database, &f.old_key, &["b"]);
    let out = ok(f.rotate(&[]));
    assert!(out.contains("left by an interrupted run"), "{out}");
    assert_eq!(objects(&f.database, &f.new_key), 2);

    // Killed after recording the cutover, before moving anything; the
    // database changed since (someone started the server on it): the copy
    // is discarded and the rotation runs again.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    rotated_copy(&f);
    journal(&f, PRE);
    add(&f.database, &f.old_key, &["late"]);
    let out = ok(f.rotate(&[]));
    assert!(out.contains("Discarded"), "{out}");
    assert_eq!(objects(&f.database, &f.new_key), 2);
    assert!(!f.data.join(PRE).exists());

    // Killed while moving the old database aside.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    rotated_copy(&f);
    journal(&f, PRE);
    move_database(&f.data, &f.data.join(PRE), true);
    let out = ok(f.rotate(&[]));
    assert!(out.contains("Resuming the interrupted cutover"), "{out}");
    assert_eq!(objects(&f.database, &f.new_key), 1);
    assert_eq!(
        objects(&f.data.join(PRE).join("kmip.sqlite"), &f.old_key),
        1
    );
    assert!(!sidecar(&f.database, ".rotation.json").exists());
    assert!(ok(f.rotate(&[])).contains("nothing to rotate"));

    // Killed after installing the copy, before removing the record.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let rotated = rotated_copy(&f);
    journal(&f, PRE);
    move_database(&f.data, &f.data.join(PRE), false);
    fs::rename(&rotated, &f.database).unwrap();
    let out = ok(f.rotate(&[&"--checkpoint-output", &f.path("cp.json")]));
    assert!(out.contains("Resuming"), "{out}");
    ok(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.new_key,
        &"--audit-checkpoint",
        &f.path("cp.json"),
    ]));

    // --revert undoes a rotation killed mid-move.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    rotated_copy(&f);
    journal(&f, PRE);
    move_database(&f.data, &f.data.join(PRE), true);
    let out = ok(f.rotate(&[&"--revert"]));
    assert!(out.contains("Reverted an interrupted rotation"), "{out}");
    assert_eq!(objects(&f.database, &f.old_key), 1);
    assert!(!sidecar(&f.database, ".rotated").exists());
    assert!(!sidecar(&f.database, ".rotation.json").exists());
    assert!(!f.data.join(PRE).exists());

    // A revert killed after moving the rotated database aside.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    ok(f.rotate(&[]));
    let pre = f.pre_rotation().remove(0);
    let pre_name = pre.file_name().unwrap().to_str().unwrap().to_string();
    let post_name = pre_name.replace("pre-", "post-");
    fs::write(
        sidecar(&f.database, ".revert.json"),
        serde_json::json!({"pre": pre_name, "post": post_name}).to_string(),
    )
    .unwrap();
    move_database(&f.data, &f.data.join(&post_name), true);
    let error = fails(f.rotate(&[]));
    assert!(error.contains("a revert was interrupted"), "{error}");
    let out = ok(f.rotate(&[&"--revert"]));
    assert!(out.contains("Resuming the interrupted revert"), "{out}");
    assert_eq!(objects(&f.database, &f.old_key), 1);
    assert_eq!(
        objects(&f.data.join(&post_name).join("kmip.sqlite"), &f.new_key),
        1
    );
    assert!(!sidecar(&f.database, ".revert.json").exists());
}

// ------------------------------------------------------------------
// Regression tests for crash recovery, locking and retention in the
// commands above.

/// Crash points exist only in debug builds of the binary, which `cargo test`
/// builds unless run with `--release`.
fn crash_points() -> bool {
    cfg!(debug_assertions)
}
/// Run the binary with a crash point: a debug build exits with status 86
/// at the named step, leaving files as a killed process would.
fn cli_crashing_at(point: &str, args: &[&dyn AsRef<std::ffi::OsStr>]) -> Output {
    Command::new(BIN)
        .args(args.iter().map(|a| a.as_ref()))
        .env("KEYTEND_KMIP_SERVER_TEST_FAULT", point)
        .output()
        .unwrap()
}
fn crashed(output: Output) {
    assert_eq!(
        output.status.code(),
        Some(86),
        "expected the crash point to stop the run\nstdout: {}\nstderr: {}",
        stdout(&output),
        stderr(&output)
    );
}
impl Fixture {
    fn rotate_args<'a>(
        &'a self,
        extra: &[&'a dyn AsRef<std::ffi::OsStr>],
    ) -> Vec<&'a dyn AsRef<std::ffi::OsStr>> {
        let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
            &"rotate-master-key",
            &"--in-place",
            &"--database",
            &self.database,
            &"--master-key",
            &self.new_key,
            &"--previous-master-key",
            &self.old_key,
        ];
        args.extend_from_slice(extra);
        args
    }
    fn checkpoint(&self, name: &str, key: &Path) -> PathBuf {
        let path = self.path(name);
        Store::open_read_only(&self.database, key)
            .unwrap()
            .write_audit_checkpoint(&path, None)
            .unwrap();
        path
    }
    /// Roll the store back to an earlier copy so that `floor` rejects it.
    fn rolled_back(&self) -> PathBuf {
        add(&self.database, &self.old_key, &["a"]);
        let early = self.path("early.sqlite");
        Store::open_read_only(&self.database, &self.old_key)
            .unwrap()
            .backup(&early)
            .unwrap();
        add(&self.database, &self.old_key, &["b"]);
        let floor = self.checkpoint("floor.json", &self.old_key);
        fs::copy(&early, &self.database).unwrap();
        assert!(
            Store::open_read_only(&self.database, &self.old_key)
                .unwrap()
                .verify_audit_checkpoint(&floor)
                .is_err()
        );
        floor
    }
}
fn listing(f: &Fixture) -> Vec<(String, Vec<u8>)> {
    names(&f.data)
        .into_iter()
        // The lock file names its latest holder; everything else must stay.
        .filter(|n| f.data.join(n).is_file() && !n.ends_with(".lock"))
        .map(|n| {
            let bytes = fs::read(f.data.join(&n)).unwrap();
            (n, bytes)
        })
        .collect()
}

#[test]
fn resumed_rotation_checks_the_audit_floor_before_moving_or_issuing_checkpoints() {
    if !crash_points() {
        return;
    }
    // A recorded cutover whose source fails the floor.
    let f = Fixture::new();
    let floor = f.rolled_back();
    rotated_copy(&f);
    journal(&f, PRE);
    let before = listing(&f);
    let laundered = f.path("laundered.json");
    for _ in 0..2 {
        // Retrying after a rejection changes nothing either.
        let error = fails(f.rotate(&[
            &"--audit-checkpoint",
            &floor,
            &"--checkpoint-output",
            &laundered,
        ]));
        assert!(
            error.contains("older than or diverges from the required checkpoint"),
            "{error}"
        );
        assert!(error.contains("nothing changed"), "{error}");
        assert_eq!(listing(&f), before);
        assert!(!laundered.exists());
        assert!(!f.data.join(PRE).exists());
    }
    // --revert drops the unused copy; the store is still the old one.
    ok(f.rotate(&[&"--revert"]));
    assert!(!sidecar(&f.database, ".rotated").exists());
    assert_eq!(objects(&f.database, &f.old_key), 1);

    // The same after a crash that had moved the main file aside.
    let f = Fixture::new();
    let floor = f.rolled_back();
    crashed(cli_crashing_at("rotation-moved-main", &f.rotate_args(&[])));
    assert!(f.pre_rotation().len() == 1 && !f.database.exists());
    let error = fails(f.rotate(&[
        &"--audit-checkpoint",
        &floor,
        &"--checkpoint-output",
        &laundered,
    ]));
    assert!(error.contains("Nothing was installed"), "{error}");
    assert!(error.contains("--revert"), "{error}");
    assert!(!f.database.exists() && !laundered.exists());
    ok(f.rotate(&[&"--revert"]));
    assert_eq!(objects(&f.database, &f.old_key), 1);

    // And after a crash that had installed the copy: no checkpoint for the
    // rolled-back state is issued.
    let f = Fixture::new();
    let floor = f.rolled_back();
    crashed(cli_crashing_at("rotation-installed", &f.rotate_args(&[])));
    let error = fails(f.rotate(&[
        &"--audit-checkpoint",
        &floor,
        &"--checkpoint-output",
        &laundered,
    ]));
    assert!(error.contains("earlier run already installed"), "{error}");
    assert!(!laundered.exists());
    assert!(sidecar(&f.database, ".rotation.json").exists());
}

#[test]
fn immutable_reads_require_and_hold_the_writer_lock() {
    // Immutable reads need the lock file and hold off writers.
    let f = Fixture::new();
    if std::os::unix::fs::MetadataExt::uid(&fs::metadata(&f.data).unwrap()) == 0 {
        return;
    }
    add(&f.database, &f.old_key, &["a"]);
    fs::set_permissions(&f.data, fs::Permissions::from_mode(0o500)).unwrap();
    // No lock file: nothing would keep a server from writing meanwhile.
    let error = Store::open_read_only(&f.database, &f.old_key)
        .err()
        .expect("an unlocked immutable read was allowed")
        .to_string();
    assert!(error.contains("no lock file"), "{error}");
    let error = fails(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    assert!(error.contains("no lock file"), "{error}");
    fs::set_permissions(&f.data, fs::Permissions::from_mode(0o700)).unwrap();
    drop(WriterLock::acquire(&f.database, "serve").unwrap());
    released(&f.database);
    fs::set_permissions(&f.data, fs::Permissions::from_mode(0o500)).unwrap();
    let reader = Store::open_read_only(&f.database, &f.old_key).unwrap();
    // While the reader holds its shared lock, no writer can start.
    assert!(WriterLock::acquire(&f.database, "serve").is_err());
    drop(reader);
    released(&f.database);
    fs::set_permissions(&f.data, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn serve_refuses_to_start_during_unfinished_maintenance() {
    if !crash_points() {
        return;
    }
    // A rotation killed after moving the main file aside.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    crashed(cli_crashing_at("rotation-moved-main", &f.rotate_args(&[])));
    let error = serve(&f, &f.new_key).err().expect("serve started");
    assert!(error.contains("unfinished"), "{error}");
    assert!(!f.database.exists(), "serve created a database");
    let error = serve(&f, &f.old_key).err().expect("serve started");
    assert!(error.contains("unfinished"), "{error}");
    ok(f.rotate(&[]));
    assert_eq!(objects(&f.database, &f.new_key), 1);

    // A restore killed after moving the database aside.
    let g = Fixture::new();
    add(&g.database, &g.old_key, &["a"]);
    let backup = g.path("backup.sqlite");
    Store::open_read_only(&g.database, &g.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    let args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"restore",
        &"--from",
        &backup,
        &"--id",
        &"r1",
        &"--database",
        &g.database,
        &"--master-key",
        &g.old_key,
    ];
    crashed(cli_crashing_at("restore-moved-main", &args));
    let error = serve(&g, &g.old_key).err().expect("serve started");
    assert!(error.contains("unfinished"), "{error}");
    assert!(!g.database.exists());
    // Rotation also refuses to run over it.
    let error = fails(g.rotate(&[]));
    assert!(error.contains("unfinished"), "{error}");

    // A revert killed after moving the rotated database aside.
    let h = Fixture::new();
    add(&h.database, &h.old_key, &["a"]);
    ok(h.rotate(&[]));
    crashed(cli_crashing_at(
        "revert-aside-moved-main",
        &h.rotate_args(&[&"--revert"]),
    ));
    let error = serve(&h, &h.new_key).err().expect("serve started");
    assert!(error.contains("unfinished"), "{error}");
    ok(h.rotate(&[&"--revert"]));
    assert_eq!(objects(&h.database, &h.old_key), 1);
}

#[test]
fn retention_never_removes_the_source_or_a_live_database() {
    // The source database's own directory as --output-dir.
    let f = Fixture::new();
    let database = f.data.join("backup-20200101T000000Z.sqlite");
    add(&database, &f.old_key, &["a"]);
    let held = WriterLock::acquire(&database, "serve").unwrap();
    let live = Store::open(&database, &f.old_key).unwrap();
    let error = fails(cli(&[
        &"backup",
        &"--database",
        &database,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &f.data,
        &"--retain",
        &"1",
    ]));
    assert!(
        error.contains("--output-dir must not be the database's directory"),
        "{error}"
    );
    assert!(database.exists());
    drop(live);
    drop(held);
    released(&database);
    // In another directory: the source (by identity, through a hard link)
    // and a WAL-mode database with backup names are never pruned.
    let dir = f.path("backups");
    fs::create_dir(&dir).unwrap();
    fs::hard_link(&database, dir.join("backup-20000101T000000Z.sqlite")).unwrap();
    let other = dir.join("backup-20010101T000000Z.sqlite");
    add(&other, &f.old_key, &["x"]);
    let _other = Store::open(&other, &f.old_key).unwrap(); // keeps its -wal
    fs::write(
        dir.join("backup-20020101T000000Z.sqlite"),
        b"not a database",
    )
    .unwrap();
    ok(cli(&[
        &"backup",
        &"--database",
        &database,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &dir,
        &"--retain",
        &"1",
    ]));
    let kept = names(&dir);
    assert!(
        kept.contains(&"backup-20000101T000000Z.sqlite".to_string()),
        "{kept:?}"
    );
    assert!(
        kept.contains(&"backup-20010101T000000Z.sqlite".to_string()),
        "{kept:?}"
    );
    assert!(
        kept.contains(&"backup-20020101T000000Z.sqlite".to_string()),
        "{kept:?}"
    );
    assert_eq!(objects(&database, &f.old_key), 1);
}

#[test]
fn directory_backups_publish_the_manifest_before_pruning_and_run_one_at_a_time() {
    if !crash_points() {
        return;
    }
    // Manifest ordering and serialisation.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let dir = f.path("backups");
    fs::create_dir(&dir).unwrap();
    let second: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &dir,
        &"--retain",
        &"1",
    ];
    ok(cli(&second));
    std::thread::sleep(std::time::Duration::from_millis(1100));
    crashed(cli_crashing_at("backup-published", &second));
    // The manifest names the new backup, which exists; the old one is
    // pruned by the next run.
    let latest: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("latest.json")).unwrap()).unwrap();
    assert!(dir.join(latest["file"].as_str().unwrap()).is_file());
    assert_eq!(
        names(&dir)
            .iter()
            .filter(|n| n.ends_with("Z.sqlite"))
            .count(),
        2
    );
    std::thread::sleep(std::time::Duration::from_millis(1100));
    ok(cli(&second));
    assert_eq!(
        names(&dir)
            .iter()
            .filter(|n| n.ends_with("Z.sqlite"))
            .count(),
        1
    );
    // A second run into the same directory waits for nobody: it fails fast.
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(".backup.lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let error = fails(cli(&second));
    assert!(error.contains("another backup into"), "{error}");
}

#[test]
fn completed_restore_rechecks_its_database_and_checkpoint() {
    // A completed restore id rechecks its database and checkpoint.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let backup = f.path("early.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    ok(f.restore(&backup, "r1", &f.old_key, &[]));
    add(&f.database, &f.old_key, &["b"]);
    let cp = f.checkpoint("cp.json", &f.old_key);
    ok(f.restore(&backup, "r1", &f.old_key, &[&"--audit-checkpoint", &cp]));
    // Rolled back below the checkpoint after the restore: refused.
    fs::copy(&backup, &f.database).unwrap();
    let error = fails(f.restore(&backup, "r1", &f.old_key, &[&"--audit-checkpoint", &cp]));
    assert!(
        error.contains("older than or diverges from the required checkpoint"),
        "{error}"
    );
    // The marker names its database: another database in the directory
    // cannot reuse the id.
    let target = f.data.join("second.sqlite");
    let error = fails(cli(&[
        &"restore",
        &"--from",
        &backup,
        &"--id",
        &"r1",
        &"--database",
        &target,
        &"--master-key",
        &f.old_key,
    ]));
    assert!(error.contains("was used for"), "{error}");
    assert!(!target.exists());
    // A completed restore whose database has gone is not success either.
    fs::remove_file(&f.database).unwrap();
    let error = fails(f.restore(&backup, "r1", &f.old_key, &[]));
    assert!(error.contains("does not exist"), "{error}");
}

#[test]
fn resumed_revert_checks_the_floor_before_changing_the_live_store() {
    if !crash_points() {
        return;
    }
    // A recorded revert, resumed with a checkpoint that rejects
    // the pre-rotation database.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    ok(f.rotate(&[]));
    add(&f.database, &f.new_key, &["b"]);
    let floor = f.checkpoint("floor.json", &f.new_key);
    let pre = f.pre_rotation().remove(0);
    let pre_name = pre.file_name().unwrap().to_str().unwrap().to_string();
    fs::write(
        sidecar(&f.database, ".revert.json"),
        serde_json::json!({"pre": pre_name, "post": pre_name.replace("pre-", "post-")}).to_string(),
    )
    .unwrap();
    for _ in 0..2 {
        let error = fails(f.rotate(&[&"--revert", &"--audit-checkpoint", &floor]));
        assert!(error.contains("nothing changed"), "{error}");
        assert!(Store::master_key_opens(&f.database, &f.new_key).unwrap());
        assert_eq!(objects(&f.database, &f.new_key), 2);
    }
    // After a crash that had moved the rotated database aside, a rejection
    // says that an earlier run changed the live files.
    let g = Fixture::new();
    add(&g.database, &g.old_key, &["a"]);
    ok(g.rotate(&[]));
    add(&g.database, &g.new_key, &["b"]);
    let floor = g.checkpoint("floor.json", &g.new_key);
    crashed(cli_crashing_at(
        "revert-aside-moved-main",
        &g.rotate_args(&[&"--revert"]),
    ));
    let error = fails(g.rotate(&[&"--revert", &"--audit-checkpoint", &floor]));
    assert!(error.contains("earlier run already moved"), "{error}");
    assert!(!g.database.exists());
    // Without the rejecting checkpoint the revert completes.
    ok(g.rotate(&[&"--revert"]));
    assert_eq!(objects(&g.database, &g.old_key), 1);
}

#[test]
fn revert_refuses_an_unrelated_pre_rotation_database() {
    // A revert refuses a pre-rotation database of another store.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    ok(f.rotate(&[]));
    let unrelated = f.path("unrelated.sqlite");
    add(&unrelated, &f.old_key, &["wrong1", "wrong2"]);
    let pre = f.pre_rotation().remove(0);
    fs::copy(&unrelated, pre.join("kmip.sqlite")).unwrap();
    let error = fails(f.rotate(&[&"--revert"]));
    assert!(error.contains("not the master-key rotation"), "{error}");
    assert!(Store::master_key_opens(&f.database, &f.new_key).unwrap());
    assert_eq!(objects(&f.database, &f.new_key), 1);
    assert!(!sidecar(&f.database, ".revert.json").exists());
}

#[test]
fn torn_or_unpublished_journals_do_not_block_recovery() {
    if !crash_points() {
        return;
    }
    // A record torn by the old non-atomic write.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    rotated_copy(&f);
    fs::write(sidecar(&f.database, ".rotation.json"), b"{\"pre\":").unwrap();
    let out = ok(f.rotate(&[]));
    assert!(out.contains("Discarded"), "{out}");
    assert_eq!(objects(&f.database, &f.new_key), 1);
    let g = Fixture::new();
    add(&g.database, &g.old_key, &["a"]);
    rotated_copy(&g);
    fs::write(sidecar(&g.database, ".rotation.json"), b"").unwrap();
    ok(g.rotate(&[&"--revert"]));
    assert!(!sidecar(&g.database, ".rotation.json").exists());
    assert_eq!(objects(&g.database, &g.old_key), 1);
    // A crash while publishing a record leaves no record at all.
    let h = Fixture::new();
    add(&h.database, &h.old_key, &["a"]);
    crashed(cli_crashing_at(
        "rotation-record-staged",
        &h.rotate_args(&[]),
    ));
    assert!(!sidecar(&h.database, ".rotation.json").exists());
    assert!(h.database.exists() && h.pre_rotation().is_empty());
    ok(h.rotate(&[]));
    crashed(cli_crashing_at(
        "revert-record-staged",
        &h.rotate_args(&[&"--revert"]),
    ));
    assert!(!sidecar(&h.database, ".revert.json").exists());
    assert!(Store::master_key_opens(&h.database, &h.new_key).unwrap());
    ok(h.rotate(&[&"--revert"]));
    assert_eq!(objects(&h.database, &h.old_key), 1);
    // No staging file is left behind by the successful runs.
    assert!(
        names(&h.data)
            .iter()
            .all(|n| !n.starts_with(".keytend-kmip-server-journal-")),
        "{:?}",
        names(&h.data)
    );
}

/// The child half of the concurrency tests: commits objects through its own
/// writer and exits without closing it, so the WAL keeps its frames.
#[test]
fn child_writer() {
    let Ok(root) = std::env::var("KEYTEND_TEST_CHILD_WRITER") else {
        return;
    };
    let root = Path::new(&root);
    let database = root.join("data/kmip.sqlite");
    let key = root.join(std::env::var("KEYTEND_TEST_CHILD_KEY").unwrap());
    let prefix = key.file_stem().unwrap().to_string_lossy().into_owned();
    let _lock = WriterLock::acquire(&database, "serve (test writer)").unwrap();
    let store = Store::open(&database, &key).unwrap();
    for i in 0..200 {
        let id = format!("{prefix}-child{i}");
        store.insert(&object(&id)).unwrap();
        store.audit("alice", 1, Some(&id), 0).unwrap();
        if i == 0 {
            fs::write(root.join("started"), b"yes").unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    std::process::exit(0);
}
fn spawn_writer(f: &Fixture, key: &str) -> std::process::Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_writer", "--nocapture"])
        .env("KEYTEND_TEST_CHILD_WRITER", f.dir.path())
        .env("KEYTEND_TEST_CHILD_KEY", key)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    while !f.path("started").exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "the writer exited before committing"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    child
}

#[test]
fn checks_and_backups_run_against_concurrent_commits_and_crashes_keep_a_non_empty_wal() {
    if !crash_points() {
        return;
    }
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let mut child = spawn_writer(&f, "old.key");
    let mut counts = vec![];
    for n in 0..10 {
        ok(cli(&[
            &"check-store",
            &"--database",
            &f.database,
            &"--master-key",
            &f.old_key,
        ]));
        let backup = f.path(&format!("hot{n}.sqlite"));
        ok(cli(&[
            &"backup",
            &"--database",
            &f.database,
            &"--master-key",
            &f.old_key,
            &"--output",
            &backup,
        ]));
        counts.push(objects(&backup, &f.old_key));
    }
    assert!(child.wait().unwrap().success());
    assert!(counts.windows(2).all(|w| w[0] <= w[1]), "{counts:?}");
    assert!(counts[0] >= 1 && *counts.last().unwrap() <= 201);
    assert!(
        counts.first() < counts.last(),
        "backups did not overlap the writer: {counts:?}"
    );
    // The writer exited without a checkpoint: committed frames live in the WAL.
    assert!(fs::metadata(sidecar(&f.database, "-wal")).unwrap().len() > 0);
    assert_eq!(objects(&f.database, &f.old_key), 201);
    // A rotation killed after moving the main file keeps them.
    crashed(cli_crashing_at("rotation-moved-main", &f.rotate_args(&[])));
    let pre = f.pre_rotation().remove(0);
    assert!(
        sidecar(&f.database, "-wal").exists(),
        "the WAL had not moved yet"
    );
    ok(f.rotate(&[]));
    assert_eq!(objects(&f.database, &f.new_key), 201);
    assert_eq!(objects(&pre.join("kmip.sqlite"), &f.old_key), 201);
    // The server writes under the new key and leaves its WAL; a revert
    // killed mid-move keeps the rotated store whole.
    fs::remove_file(f.path("started")).unwrap();
    let mut child = spawn_writer(&f, "new.key");
    assert!(child.wait().unwrap().success());
    assert!(fs::metadata(sidecar(&f.database, "-wal")).unwrap().len() > 0);
    crashed(cli_crashing_at(
        "revert-aside-moved-main",
        &f.rotate_args(&[&"--revert"]),
    ));
    ok(f.rotate(&[&"--revert"]));
    assert_eq!(objects(&f.database, &f.old_key), 201);
    let post = f.data.join(
        pre.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .replace("pre-", "post-"),
    );
    assert_eq!(objects(&post.join("kmip.sqlite"), &f.new_key), 401);
}

#[test]
fn rotation_without_in_place_takes_the_writer_lock() {
    // The writable, migrating rotation open.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let held = WriterLock::acquire(&f.database, "serve").unwrap();
    let error = fails(cli(&[
        &"rotate-master-key",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--new-master-key",
        &f.new_key,
        &"--output",
        &f.path("rotated.sqlite"),
    ]));
    assert!(
        error.contains("the store is in use by a running server"),
        "{error}"
    );
    assert!(!f.path("rotated.sqlite").exists());
    drop(held);
    released(&f.database);
}

// ------------------------------------------------------------------
// Regression tests: retention under writer locks, reads during an
// unfinished cutover, and restore recovery.

/// Start the binary paused at `point` (debug builds): it creates `marker`
/// and waits until the test removes it. Returns once paused.
fn spawn_paused(
    point: &str,
    marker: &Path,
    args: &[&dyn AsRef<std::ffi::OsStr>],
) -> std::process::Child {
    let mut child = Command::new(BIN)
        .args(args.iter().map(|a| a.as_ref()))
        .env("KEYTEND_KMIP_SERVER_TEST_PAUSE", point)
        .env("KEYTEND_KMIP_SERVER_TEST_PAUSE_FILE", marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !marker.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "the command finished without pausing at {point}"
        );
        assert!(std::time::Instant::now() < deadline, "no pause at {point}");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    child
}
fn backup_into(f: &Fixture, dir: &Path, retain: &str) -> Output {
    cli(&[
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &dir,
        &"--retain",
        &retain,
    ])
}
fn next_second() {
    std::thread::sleep(std::time::Duration::from_millis(1050));
}

#[test]
fn retention_never_deletes_a_backup_a_writer_has_locked() {
    // A writer locks a candidate after it was
    // chosen for pruning.
    if !crash_points() {
        return;
    }
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let dir = f.path("backups");
    fs::create_dir(&dir).unwrap();
    ok(backup_into(&f, &dir, "1"));
    let first =
        serde_json::from_slice::<serde_json::Value>(&fs::read(dir.join("latest.json")).unwrap())
            .unwrap()["file"]
            .as_str()
            .unwrap()
            .to_string();
    next_second();
    let marker = f.path("paused");
    let args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &dir,
        &"--retain",
        &"1",
    ];
    let child = spawn_paused("retention-candidate-checked", &marker, &args);
    // A server starts on the old backup while it is planned for removal.
    let held = WriterLock::acquire(&dir.join(&first), "serve").unwrap();
    fs::remove_file(&marker).unwrap();
    let out = child.wait_with_output().unwrap();
    let text = ok(out);
    assert!(
        dir.join(&first).exists(),
        "a locked backup was deleted: {text}"
    );
    assert!(text.contains(&format!("Kept {first}")), "{text}");
    drop(held);
}

#[test]
fn reads_never_poison_an_interrupted_revert_and_wait_for_no_cutover() {
    // Reads refuse an interrupted revert without disturbing it, fail fast
    // during a cutover, and a cutover waits for a read in progress.
    if !crash_points() {
        return;
    }
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    ok(f.rotate(&[]));
    crashed(cli_crashing_at(
        "revert-back-moved-main",
        &f.rotate_args(&[&"--revert"]),
    ));
    // The old main file is live again, its sidecars still in pre-rotation.
    let error = fails(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    assert!(error.contains("unfinished"), "{error}");
    assert!(!sidecar(&f.database, "-wal").exists() || f.pre_rotation().is_empty());
    let out = ok(f.rotate(&[&"--revert"]));
    assert!(out.contains("Reverted"), "{out}");
    ok(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    // While a cutover holds the directory, reads fail fast.
    let dir = fs::File::open(&f.data).unwrap();
    rustix::fs::flock(&dir, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let error = fails(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    assert!(error.contains("is changing the database files"), "{error}");
    // Unlock explicitly: a process another test forks right now shares the
    // open file until it executes, and closing would leave the lock to it.
    rustix::fs::flock(&dir, rustix::fs::FlockOperation::Unlock).unwrap();
    drop(dir);
    // A cutover waits for a read in progress to finish.
    let reader = fs::File::open(&f.data).unwrap();
    rustix::fs::flock(&reader, rustix::fs::FlockOperation::NonBlockingLockShared).unwrap();
    let backup = f.path("b.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    let mut restore = Command::new(BIN)
        .args(["restore", "--from"])
        .arg(&backup)
        .args(["--id", "after-read", "--database"])
        .arg(&f.database)
        .arg("--master-key")
        .arg(&f.old_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(
        restore.try_wait().unwrap().is_none(),
        "the restore did not wait for the read"
    );
    assert!(!f.data.join("pre-restore-after-read").exists());
    rustix::fs::flock(&reader, rustix::fs::FlockOperation::Unlock).unwrap();
    drop(reader);
    assert!(restore.wait().unwrap().success());
}

#[test]
fn retention_only_prunes_backups_it_recorded_for_this_database() {
    // Retention never prunes another database's backups or foreign files
    // in the same directory.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let dir = f.path("backups");
    fs::create_dir(&dir).unwrap();
    // A valid backup of another database, under another key, copied in.
    let other = f.path("other.sqlite");
    add(&other, &f.other_key, &["valuable-other-key"]);
    let foreign = dir.join("backup-20000101T000000Z.sqlite");
    Store::open_read_only(&other, &f.other_key)
        .unwrap()
        .backup(&foreign)
        .unwrap();
    // Another database's own series in the same directory.
    let second = f.data.join("second.sqlite");
    add(&second, &f.old_key, &["b"]);
    ok(cli(&[
        &"backup",
        &"--database",
        &second,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &dir,
    ]));
    let second_backup =
        serde_json::from_slice::<serde_json::Value>(&fs::read(dir.join("latest.json")).unwrap())
            .unwrap()["file"]
            .as_str()
            .unwrap()
            .to_string();
    next_second();
    ok(backup_into(&f, &dir, "1"));
    next_second();
    let out = ok(backup_into(&f, &dir, "1"));
    assert!(out.contains("Removed 1 older backups"), "{out}");
    assert!(out.contains("not recorded as backups of"), "{out}");
    assert!(foreign.exists());
    assert_eq!(objects(&foreign, &f.other_key), 1);
    assert!(dir.join(&second_backup).exists());
}

#[test]
fn manual_restores_and_archive_directories_never_block_the_server() {
    // The documented manual restore.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a", "b"]);
    let backup = f.path("backup.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    add(&f.database, &f.old_key, &["c"]);
    let aside = f.data.join("pre-restore-20261105T021500Z");
    move_database(&f.data, &aside, false);
    fs::copy(&backup, &f.database).unwrap();
    fs::set_permissions(&f.database, fs::Permissions::from_mode(0o600)).unwrap();
    // An unrelated empty archive directory too.
    fs::create_dir(f.data.join("pre-restore-not-a-restore")).unwrap();
    let server = serve(&f, &f.old_key).expect("serve refused a manual restore");
    drop(server);
    assert_eq!(objects(&f.database, &f.old_key), 2);
    ok(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    ok(f.rotate(&[]));
    // A CLI restore whose id names a directory it did not create refuses.
    let error = fails(f.restore(&backup, "20261105T021500Z", &f.old_key, &[]));
    assert!(error.contains("already exists"), "{error}");
}

#[test]
fn interrupted_restores_complete_and_name_the_id_to_retry() {
    // The printed recovery must work.
    if !crash_points() {
        return;
    }
    let restore_args = |f: &Fixture, backup: &Path, id: &str| -> Output {
        let args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
            &"restore",
            &"--from",
            &backup,
            &"--id",
            &id,
            &"--database",
            &f.database,
            &"--master-key",
            &f.old_key,
        ];
        Command::new(BIN)
            .args(args.iter().map(|a| a.as_ref()))
            .output()
            .unwrap()
    };
    let setup = || {
        let f = Fixture::new();
        add(&f.database, &f.old_key, &["a"]);
        let backup = f.path("backup.sqlite");
        Store::open_read_only(&f.database, &f.old_key)
            .unwrap()
            .backup(&backup)
            .unwrap();
        add(&f.database, &f.old_key, &["b"]);
        (f, backup)
    };
    let args_for = |f: &Fixture, backup: &Path, id: &str| -> Vec<std::ffi::OsString> {
        vec![
            "restore".into(),
            "--from".into(),
            backup.into(),
            "--id".into(),
            id.into(),
            "--database".into(),
            f.database.clone().into(),
            "--master-key".into(),
            f.old_key.clone().into(),
        ]
    };
    let crash = |point: &str, args: &[std::ffi::OsString]| {
        let refs: Vec<&dyn AsRef<std::ffi::OsStr>> = args
            .iter()
            .map(|a| a as &dyn AsRef<std::ffi::OsStr>)
            .collect();
        crashed(cli_crashing_at(point, &refs));
    };

    // Installed, completion record not yet published.
    let (f, backup) = setup();
    crash("restore-marker-staged", &args_for(&f, &backup, "first"));
    assert!(serve(&f, &f.old_key).is_err());
    // A different id is refused and names the unfinished one; following
    // that advice completes it.
    let error = fails(restore_args(&f, &backup, "second"));
    assert!(error.contains("--id first"), "{error}");
    let out = ok(restore_args(&f, &backup, "first"));
    assert!(
        out.contains("Completed the interrupted restore first"),
        "{out}"
    );
    assert!(f.data.join(".restore-first").exists());
    assert_eq!(objects(&f.database, &f.old_key), 1);
    drop(serve(&f, &f.old_key).expect("serve after the completed restore"));
    ok(restore_args(&f, &backup, "first"));

    // Killed after moving the previous database aside: completes too.
    let (f, backup) = setup();
    crash("restore-moved-main", &args_for(&f, &backup, "r"));
    assert!(!f.database.exists());
    let out = ok(restore_args(&f, &backup, "r"));
    assert!(out.contains("Completed the interrupted restore r"), "{out}");
    assert_eq!(objects(&f.database, &f.old_key), 1);
    assert_eq!(
        objects(
            &f.data.join("pre-restore-r").join("kmip.sqlite"),
            &f.old_key
        ),
        2
    );

    // Resumed with a checkpoint the backup does not satisfy: the verified
    // cutover still completes (there is no undo state), then the checkpoint
    // check fails and says the restore completed; nothing blocks.
    let (f, backup) = setup();
    let cp = f.checkpoint("cp.json", &f.old_key);
    crash("restore-moved-main", &args_for(&f, &backup, "r"));
    let error = fails(f.restore(&backup, "r", &f.old_key, &[&"--audit-checkpoint", &cp]));
    assert!(error.contains("restore r completed"), "{error}");
    assert_eq!(objects(&f.database, &f.old_key), 1);
    assert!(!sidecar(&f.database, ".restore.json").exists());
    drop(serve(&f, &f.old_key).expect("serve after the completed restore"));
    // On a new volume (no previous database) the same completion works.
    let g = Fixture::new();
    crash("restore-marker-staged", &args_for(&g, &backup, "fresh"));
    ok(restore_args(&g, &backup, "fresh"));
    assert_eq!(objects(&g.database, &f.old_key), 1);
}

// ------------------------------------------------------------------
// Regression tests: writer lock files during retention, restores that
// only complete, and reverts that leave no record.

#[test]
fn retention_never_creates_or_removes_a_writer_lock_file() {
    // A writer that locks a candidate during
    // retention keeps its lock inode and its exclusion.
    if !crash_points() {
        return;
    }
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let dir = f.path("backups");
    fs::create_dir(&dir).unwrap();
    ok(backup_into(&f, &dir, "5"));
    let first =
        serde_json::from_slice::<serde_json::Value>(&fs::read(dir.join("latest.json")).unwrap())
            .unwrap()["file"]
            .as_str()
            .unwrap()
            .to_string();
    // A backup cannot be served in place: it is read-only.
    assert_eq!(
        fs::metadata(dir.join(&first)).unwrap().permissions().mode() & 0o777,
        0o400
    );
    assert!(Store::open(&dir.join(&first), &f.old_key).is_err());
    next_second();
    let marker = f.path("paused");
    let args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &dir,
        &"--retain",
        &"1",
    ];
    let child = spawn_paused("retention-candidate-checked", &marker, &args);
    // A writer starts on the candidate after it was checked.
    let held = WriterLock::acquire(&dir.join(&first), "serve").unwrap();
    fs::remove_file(&marker).unwrap();
    let text = ok(child.wait_with_output().unwrap());
    assert!(text.contains(&format!("Kept {first}")), "{text}");
    assert!(dir.join(&first).exists());
    // The writer's lock file is still there and still excludes others.
    assert!(WriterLock::path_for(&dir.join(&first)).exists());
    assert!(WriterLock::acquire(&dir.join(&first), "serve").is_err());
    drop(held);
    // No lock file is ever created for the backups retention removes.
    next_second();
    let before: Vec<String> = names(&dir)
        .into_iter()
        .filter(|n| n.ends_with(".lock"))
        .collect();
    ok(backup_into(&f, &dir, "1"));
    let after: Vec<String> = names(&dir)
        .into_iter()
        .filter(|n| n.ends_with(".lock"))
        .collect();
    assert_eq!(before, after);
}

#[test]
fn an_interrupted_restore_only_ever_completes() {
    // No undo state: a retry completes the
    // verified cutover, and a checkpoint given then is checked afterwards.
    if !crash_points() {
        return;
    }
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let backup = f.path("backup.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    add(&f.database, &f.old_key, &["b"]);
    let floor = f.checkpoint("floor.json", &f.old_key);
    let args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"restore",
        &"--from",
        &backup,
        &"--id",
        &"r",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ];
    crashed(cli_crashing_at("restore-marker-staged", &args));
    // Retried with a newer floor: the cutover completes, then the floor
    // check fails and says so.
    let error = fails(f.restore(&backup, "r", &f.old_key, &[&"--audit-checkpoint", &floor]));
    assert!(error.contains("restore r completed"), "{error}");
    assert!(!sidecar(&f.database, ".restore.json").exists());
    assert!(f.data.join(".restore-r").exists());
    assert!(!f.data.join("failed-restore-r").exists());
    assert_eq!(objects(&f.database, &f.old_key), 1);
    assert_eq!(
        objects(
            &f.data.join("pre-restore-r").join("kmip.sqlite"),
            &f.old_key
        ),
        2
    );
    // Nothing blocks: the server starts (without the floor), and the same
    // id is a no-op.
    drop(serve(&f, &f.old_key).expect("serve after the completed restore"));
    let out = ok(f.restore(&backup, "r", &f.old_key, &[]));
    assert!(out.contains("already completed"), "{out}");
    // Going back, as the documentation says: back up the previous database
    // and restore that copy with a new id.
    let previous = f.path("previous.sqlite");
    ok(cli(&[
        &"backup",
        &"--database",
        &f.data.join("pre-restore-r").join("kmip.sqlite"),
        &"--master-key",
        &f.old_key,
        &"--output",
        &previous,
    ]));
    ok(f.restore(
        &previous,
        "back",
        &f.old_key,
        &[&"--audit-checkpoint", &floor],
    ));
    assert_eq!(objects(&f.database, &f.old_key), 2);
    drop(serve(&f, &f.old_key).expect("serve after going back"));
}

#[test]
fn a_revert_never_leaves_a_rotation_record_behind() {
    // Reverts killed at any point leave no rotation, revert or restore
    // record once retried.
    if !crash_points() {
        return;
    }
    let settled = |f: &Fixture| {
        for record in [".rotation.json", ".revert.json", ".restore.json"] {
            assert!(
                !sidecar(&f.database, record).exists(),
                "{record} left behind"
            );
        }
        drop(serve(f, &f.old_key).expect("serve after the revert"));
    };
    // A revert of an installed rotation, killed right after its record.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    crashed(cli_crashing_at("rotation-installed", &f.rotate_args(&[])));
    crashed(cli_crashing_at(
        "revert-recorded",
        &f.rotate_args(&[&"--revert"]),
    ));
    ok(f.rotate(&[&"--revert"]));
    assert_eq!(objects(&f.database, &f.old_key), 1);
    settled(&f);
    // An undo of a half-moved rotation, killed after it dropped the record.
    let g = Fixture::new();
    add(&g.database, &g.old_key, &["a"]);
    crashed(cli_crashing_at("rotation-moved-main", &g.rotate_args(&[])));
    crashed(cli_crashing_at(
        "undo-record-removed",
        &g.rotate_args(&[&"--revert"]),
    ));
    ok(g.rotate(&[&"--revert"]));
    assert!(!sidecar(&g.database, ".rotated").exists());
    assert_eq!(objects(&g.database, &g.old_key), 1);
    settled(&g);
}

// ------------------------------------------------------------------
// Regression tests: content-based identity of backups, mount points,
// archive names and the final record check.

/// Replace `path` by a byte-identical copy with a new inode, keeping its
/// mode: what a remount (a new device number) or a file-level copy looks
/// like to a check by device and inode.
fn same_content_new_inode(path: &Path) {
    let mode = fs::metadata(path).unwrap().permissions().mode();
    let copy = sidecar(path, ".copy");
    fs::copy(path, &copy).unwrap();
    fs::set_permissions(&copy, fs::Permissions::from_mode(mode)).unwrap();
    fs::rename(&copy, path).unwrap();
}
/// Run the binary in a new user and mount namespace with `bind` bind-
/// mounted onto itself (a file mount point), or None if unavailable.
fn with_file_mount(bind: &Path, args: &[&dyn AsRef<std::ffi::OsStr>]) -> Option<Output> {
    if Command::new("unshare")
        .args(["-Ur", "-m", "true"])
        .output()
        .ok()?
        .status
        .success()
    {
        let mut script = format!(
            "mount --bind '{0}' '{0}' && exec '{1}'",
            bind.display(),
            BIN
        );
        for arg in args {
            script.push_str(&format!(" '{}'", arg.as_ref().to_string_lossy()));
        }
        Some(
            Command::new("unshare")
                .args(["-Ur", "-m", "sh", "-c", &script])
                .output()
                .unwrap(),
        )
    } else {
        None
    }
}

#[test]
fn backups_and_restores_are_recognised_by_content_not_inode() {
    // Retention and restore recognise a copied or remounted file (new inode)
    // by its content.
    if !crash_points() {
        return;
    }
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let dir = f.path("backups");
    fs::create_dir(&dir).unwrap();
    ok(backup_into(&f, &dir, "5"));
    let first =
        serde_json::from_slice::<serde_json::Value>(&fs::read(dir.join("latest.json")).unwrap())
            .unwrap()["file"]
            .as_str()
            .unwrap()
            .to_string();
    same_content_new_inode(&dir.join(&first));
    next_second();
    let out = ok(backup_into(&f, &dir, "1"));
    assert!(
        out.contains(&format!("Removed 1 older backups: {first}")),
        "{out}"
    );
    // A restore interrupted after installing its copy, whose installed file
    // then has a new inode, still completes.
    let backup = f.path("backup.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    let args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"restore",
        &"--from",
        &backup,
        &"--id",
        &"r",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ];
    crashed(cli_crashing_at("restore-marker-staged", &args));
    same_content_new_inode(&f.database);
    let out = ok(f.restore(&backup, "r", &f.old_key, &[]));
    assert!(out.contains("Completed the interrupted restore r"), "{out}");
}

#[test]
fn restore_recovery_advice_can_be_followed() {
    // The by-hand advice must work while the
    // intent record exists.
    if !crash_points() {
        return;
    }
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let backup = f.path("backup.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    add(&f.database, &f.old_key, &["b"]);
    let args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"restore",
        &"--from",
        &backup,
        &"--id",
        &"r",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ];
    crashed(cli_crashing_at("restore-marker-staged", &args));
    // Outside interference: the installed file is replaced by another one.
    let other = f.path("other.sqlite");
    Store::open_read_only(
        &f.data.join("pre-restore-r").join("kmip.sqlite"),
        &f.old_key,
    )
    .unwrap()
    .backup(&other)
    .unwrap();
    fs::copy(&other, &f.database).unwrap();
    let error = fails(f.restore(&backup, "r", &f.old_key, &[]));
    assert!(!error.contains("check it with check-store"), "{error}");
    assert!(error.contains("copy"), "{error}");
    // Follow it: check a copy in a separate directory, then finish by hand.
    let isolated = f.path("isolated");
    fs::create_dir(&isolated).unwrap();
    fs::set_permissions(&isolated, fs::Permissions::from_mode(0o700)).unwrap();
    fs::copy(&f.database, isolated.join("kmip.sqlite")).unwrap();
    ok(cli(&[
        &"check-store",
        &"--database",
        &isolated.join("kmip.sqlite"),
        &"--master-key",
        &f.old_key,
    ]));
    fs::remove_file(sidecar(&f.database, ".restore.json")).unwrap();
    drop(serve(&f, &f.old_key).expect("serve after the documented recovery"));
}

#[test]
fn a_database_file_mount_point_is_refused_before_any_record() {
    // A database file that is a mount point is refused before a restore
    // writes any record.
    if !crash_points() {
        return;
    }
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let backup = f.path("backup.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    let args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"restore",
        &"--from",
        &backup,
        &"--id",
        &"r",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ];
    let Some(out) = with_file_mount(&f.database, &args) else {
        return; // no unprivileged mount namespaces here
    };
    let error = fails(out);
    assert!(error.contains("mount point"), "{error}");
    assert!(!sidecar(&f.database, ".restore.json").exists());
    assert!(!f.data.join("pre-restore-r").exists());
    let rotate = f.rotate_args(&[]);
    let error = fails(with_file_mount(&f.database, &rotate).unwrap());
    assert!(error.contains("mount point"), "{error}");
    assert!(!sidecar(&f.database, ".rotation.json").exists());
    // An intent whose cutover never moved anything: a rerun clears it when
    // it cannot proceed, and completes it when it can.
    crashed(cli_crashing_at("restore-recorded", &args));
    assert!(sidecar(&f.database, ".restore.json").exists());
    let error = fails(with_file_mount(&f.database, &args).unwrap());
    assert!(error.contains("nothing was moved"), "{error}");
    assert!(!sidecar(&f.database, ".restore.json").exists());
    ok(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    crashed(cli_crashing_at("restore-recorded", &args));
    let out = ok(f.restore(&backup, "r", &f.old_key, &[]));
    assert!(out.contains("Completed the interrupted restore r"), "{out}");
}

#[test]
fn rotation_archive_names_never_collide() {
    // Names already taken for the next seconds.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    for t in now..now + 20 {
        let stamp = keytend_kmip_server::maintenance::compact_utc(t);
        fs::create_dir(f.data.join(format!("post-rotation-{stamp}"))).unwrap();
    }
    for _ in 0..2 {
        ok(f.rotate(&[]));
        ok(f.rotate(&[&"--revert"]));
    }
    assert!(Store::master_key_opens(&f.database, &f.old_key).unwrap());
    assert_eq!(objects(&f.database, &f.old_key), 1);
}

#[test]
fn the_final_record_check_runs_under_the_locks() {
    // Another operation cannot slip in between a
    // finished cutover and its final check.
    if !crash_points() {
        return;
    }
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let backup = f.path("backup.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    let marker = f.path("paused");
    let args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"restore",
        &"--from",
        &backup,
        &"--id",
        &"first",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ];
    let child = spawn_paused("settling", &marker, &args);
    let error = fails(f.restore(&backup, "second", &f.old_key, &[]));
    assert!(error.contains("the store is in use"), "{error}");
    fs::remove_file(&marker).unwrap();
    ok(child.wait_with_output().unwrap());
    assert!(!sidecar(&f.database, ".restore.json").exists());
}

// ------------------------------------------------------------------
// Commands the Helm hooks rely on.

#[test]
fn backup_if_exists_and_several_master_keys() {
    let f = Fixture::new();
    let root = f.dir.path().to_path_buf();
    // No database yet (a server that never started).
    let missing: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &root,
    ];
    fails(cli(&missing));
    let mut if_exists = missing.clone();
    if_exists.push(&"--if-exists");
    let out = ok(cli(&if_exists));
    assert!(out.contains("nothing to back up"), "{out}");
    // Several keys: the one that opens the store is used and named.
    add(&f.database, &f.old_key, &["a"]);
    let out = ok(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.other_key,
        &"--master-key",
        &f.old_key,
    ]));
    assert!(
        out.contains(&format!("Master key {} opens", f.old_key.display())),
        "{out}"
    );
    let dir = f.path("backups");
    fs::create_dir(&dir).unwrap();
    let out = ok(cli(&[
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.new_key,
        &"--master-key",
        &f.old_key,
        &"--output-dir",
        &dir,
        &"--if-exists",
    ]));
    assert!(
        out.contains(&format!("Master key {} opens", f.old_key.display())),
        "{out}"
    );
    assert!(out.contains("written and verified: 1 objects"), "{out}");
    let error = fails(cli(&[
        &"backup",
        &"--database",
        &f.database,
        &"--master-key",
        &f.new_key,
        &"--master-key",
        &f.other_key,
        &"--output",
        &f.path("x.sqlite"),
    ]));
    assert!(
        error.contains("none of the 2 --master-key files opens"),
        "{error}"
    );
    // A candidate that is no key file at all is skipped with a note.
    let bad = f.path("not-a-key");
    fs::write(&bad, b"short").unwrap();
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o600)).unwrap();
    let run = cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &bad,
        &"--master-key",
        &f.path("missing.key"),
        &"--master-key",
        &f.old_key,
    ]);
    assert!(
        stderr(&run).contains("note: skipped --master-key"),
        "{}",
        stderr(&run)
    );
    ok(run);
    // One key: as before, nothing extra is printed.
    let out = ok(cli(&[
        &"check-store",
        &"--database",
        &f.database,
        &"--master-key",
        &f.old_key,
    ]));
    assert_eq!(out, "Master key, object records and audit chain verified\n");
}

#[test]
fn a_completed_restore_id_is_bound_to_its_backup() {
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let first = f.path("first.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&first)
        .unwrap();
    add(&f.database, &f.old_key, &["b"]);
    let second = f.path("second.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&second)
        .unwrap();
    ok(f.restore(&first, "r", &f.old_key, &[]));
    // Another backup under the same id: refused, nothing changed.
    let error = fails(f.restore(&second, "r", &f.old_key, &[]));
    assert!(
        error.contains("restore id r was already used for"),
        "{error}"
    );
    assert!(error.contains("use a new id"), "{error}");
    assert_eq!(objects(&f.database, &f.old_key), 1);
    // The same backup, or one already pruned: a no-op.
    assert!(ok(f.restore(&first, "r", &f.old_key, &[])).contains("already completed"));
    fs::remove_file(&first).unwrap();
    assert!(ok(f.restore(&first, "r", &f.old_key, &[])).contains("already completed"));
    // A byte-identical copy at another path is the same backup.
    let copy = f.path("copy.sqlite");
    fs::copy(&second, &copy).unwrap();
    ok(f.restore(&second, "s", &f.old_key, &[]));
    assert!(ok(f.restore(&copy, "s", &f.old_key, &[])).contains("already completed"));
}

// ------------------------------------------------------------------
// Regression tests: archives of an unfinished cutover, backup
// --if-exists, and completed restore ids.

#[test]
fn reads_of_an_archive_in_an_unfinished_cutover_are_refused() {
    // Archives of an unfinished rotation or revert cannot be read, by
    // absolute or relative path, until the cutover completes.
    if !crash_points() {
        return;
    }
    let check = |path: &Path, key: &Path| {
        cli(&[&"check-store", &"--database", &path, &"--master-key", &key])
    };
    // Rotation killed after moving the main file into its archive.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    crashed(cli_crashing_at("rotation-moved-main", &f.rotate_args(&[])));
    let pre = f.pre_rotation().remove(0);
    let error = fails(check(&pre.join("kmip.sqlite"), &f.old_key));
    assert!(error.contains("unfinished"), "{error}");
    // Relative paths, from the archive and from the live directory, are refused too.
    let relative = |dir: &Path, path: &str| {
        Command::new(BIN)
            .current_dir(dir)
            .args(["check-store", "--database", path, "--master-key"])
            .arg(&f.old_key)
            .output()
            .unwrap()
    };
    let archive = pre.file_name().unwrap().to_str().unwrap().to_string();
    for (dir, path) in [
        (pre.clone(), "kmip.sqlite".to_string()),
        (f.data.clone(), format!("{archive}/kmip.sqlite")),
    ] {
        let error = fails(relative(&dir, &path));
        assert!(error.contains("unfinished"), "{path}: {error}");
    }
    assert!(
        !pre.join("kmip.sqlite-shm").exists() && !pre.join("kmip.sqlite-wal").exists(),
        "the read created sidecars"
    );
    ok(f.rotate(&[]));
    // Once the cutover is complete, its archive reads normally.
    ok(check(&pre.join("kmip.sqlite"), &f.old_key));
    // Revert killed after moving the rotated main file aside.
    let g = Fixture::new();
    add(&g.database, &g.old_key, &["a"]);
    ok(g.rotate(&[]));
    crashed(cli_crashing_at(
        "revert-aside-moved-main",
        &g.rotate_args(&[&"--revert"]),
    ));
    let post = names(&g.data)
        .into_iter()
        .find(|n| n.starts_with("post-rotation-"))
        .map(|n| g.data.join(n))
        .unwrap();
    let error = fails(check(&post.join("kmip.sqlite"), &g.new_key));
    assert!(error.contains("unfinished"), "{error}");
    ok(g.rotate(&[&"--revert"]));
    assert_eq!(objects(&g.database, &g.old_key), 1);
}

#[test]
fn backup_if_exists_only_succeeds_for_a_database_that_is_really_absent() {
    // backup --if-exists succeeds only when the store is genuinely absent,
    // not when a cutover moved it aside or it cannot be inspected.
    if !crash_points() {
        return;
    }
    let if_exists = |f: &Fixture| {
        cli(&[
            &"backup",
            &"--database",
            &f.database,
            &"--master-key",
            &f.old_key,
            &"--output",
            &f.path("b.sqlite"),
            &"--if-exists",
        ])
    };
    // A directory that does not exist yet: genuinely absent.
    let f = Fixture::new();
    fs::remove_dir(&f.data).unwrap();
    assert!(ok(if_exists(&f)).contains("nothing to back up"));
    // An unfinished rotation or restore with the main file moved aside.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    crashed(cli_crashing_at("rotation-moved-main", &f.rotate_args(&[])));
    let error = fails(if_exists(&f));
    assert!(error.contains("unfinished"), "{error}");
    let g = Fixture::new();
    add(&g.database, &g.old_key, &["a"]);
    let backup = g.path("backup.sqlite");
    Store::open_read_only(&g.database, &g.old_key)
        .unwrap()
        .backup(&backup)
        .unwrap();
    let args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"restore",
        &"--from",
        &backup,
        &"--id",
        &"r",
        &"--database",
        &g.database,
        &"--master-key",
        &g.old_key,
    ];
    crashed(cli_crashing_at("restore-moved-main", &args));
    let error = fails(if_exists(&g));
    assert!(error.contains("unfinished"), "{error}");
    // A store that cannot be inspected is an error, not absence.
    let h = Fixture::new();
    if std::os::unix::fs::MetadataExt::uid(&fs::metadata(&h.data).unwrap()) == 0 {
        return;
    }
    add(&h.database, &h.old_key, &["a"]);
    fs::set_permissions(&h.data, fs::Permissions::from_mode(0o000)).unwrap();
    let result = if_exists(&h);
    fs::set_permissions(&h.data, fs::Permissions::from_mode(0o700)).unwrap();
    let error = fails(result);
    assert!(!error.contains("nothing to back up"), "{error}");
}

#[test]
fn a_completed_restore_id_refuses_symlinked_and_unreadable_backups() {
    // A completed restore id refuses another backup through a symlink and
    // treats an unreadable path as an error, not a no-op.
    let f = Fixture::new();
    add(&f.database, &f.old_key, &["a"]);
    let first = f.path("first.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&first)
        .unwrap();
    add(&f.database, &f.old_key, &["b"]);
    let other = f.path("other");
    fs::create_dir(&other).unwrap();
    let second = other.join("second.sqlite");
    Store::open_read_only(&f.database, &f.old_key)
        .unwrap()
        .backup(&second)
        .unwrap();
    ok(f.restore(&first, "r", &f.old_key, &[]));
    // Another backup through a symlink: refused.
    let link = f.path("link.sqlite");
    std::os::unix::fs::symlink(&second, &link).unwrap();
    let error = fails(f.restore(&link, "r", &f.old_key, &[]));
    assert!(error.contains("must be a regular file"), "{error}");
    // An unreadable path: an error, not a no-op.
    if std::os::unix::fs::MetadataExt::uid(&fs::metadata(&other).unwrap()) != 0 {
        fs::set_permissions(&other, fs::Permissions::from_mode(0o000)).unwrap();
        let result = f.restore(&second, "r", &f.old_key, &[]);
        fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).unwrap();
        let error = fails(result);
        assert!(!error.contains("already completed"), "{error}");
    }
    assert_eq!(objects(&f.database, &f.old_key), 1);
    // A backup that is really gone stays a no-op.
    fs::remove_file(&first).unwrap();
    assert!(ok(f.restore(&first, "r", &f.old_key, &[])).contains("already completed"));
}
