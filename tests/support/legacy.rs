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

//! Independently encode the schema-17 layout and v1 MAC, without Store writers.
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rand::rand_bytes,
    sign::Signer,
    symm::{Cipher, encrypt_aead},
};
use rusqlite::{Connection, params};
use std::path::Path;

pub fn write(path: &Path, key_path: &Path, objects: &[serde_json::Value], schema: u32) {
    if path.exists() {
        std::fs::remove_file(path).unwrap();
    }
    let key = std::fs::read(key_path).unwrap();
    fn seal(key: &[u8], aad: &[u8], value: &[u8]) -> Vec<u8> {
        let mut nonce = [0; 12];
        rand_bytes(&mut nonce).unwrap();
        let mut tag = [0; 16];
        let ct = encrypt_aead(
            Cipher::aes_256_gcm(),
            key,
            Some(&nonce),
            aad,
            value,
            &mut tag,
        )
        .unwrap();
        [vec![1], nonce.to_vec(), tag.to_vec(), ct].concat()
    }
    let conn = Connection::open(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    conn.execute_batch("CREATE TABLE meta(name TEXT PRIMARY KEY,value BLOB NOT NULL);
        CREATE TABLE objects(id TEXT PRIMARY KEY,owner TEXT NOT NULL,sealed BLOB NOT NULL);
        CREATE TABLE audit(seq INTEGER PRIMARY KEY,timestamp INTEGER NOT NULL,principal TEXT NOT NULL,operation INTEGER NOT NULL,object_id TEXT,status INTEGER NOT NULL,previous BLOB NOT NULL,mac BLOB NOT NULL);").unwrap();
    conn.execute(
        "INSERT INTO meta VALUES('key-check',?1)",
        [seal(
            &key,
            b"keytend-kmip-server key check v1",
            b"keytend-kmip-server v1",
        )],
    )
    .unwrap();
    let mut previous = vec![0u8; 32];
    for (index, value) in objects.iter().enumerate() {
        let id = value["id"].as_str().unwrap();
        let owner = value["owner"].as_str().unwrap();
        let aad = format!("keytend-kmip-server object v1\0{owner}\0{id}");
        let encrypted = seal(&key, aad.as_bytes(), &serde_json::to_vec(value).unwrap());
        conn.execute(
            "INSERT INTO objects VALUES(?1,?2,?3)",
            params![id, owner, encrypted],
        )
        .unwrap();
        let seq = (index + 1) as i64;
        let time = 1234i64;
        let op = 1u32;
        let status = 0u32;
        let signing_key = PKey::hmac(&key).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &signing_key).unwrap();
        signer.update(b"keytend-kmip-server audit v1\0").unwrap();
        signer
            .update(
                &serde_json::to_vec(&(
                    seq,
                    time,
                    owner,
                    op,
                    Some(id),
                    status,
                    hex::encode(&previous),
                ))
                .unwrap(),
            )
            .unwrap();
        let mac = signer.sign_to_vec().unwrap();
        conn.execute(
            "INSERT INTO audit VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![seq, time, owner, op, id, status, previous, mac],
        )
        .unwrap();
        previous = mac;
    }
    conn.pragma_update(None, "user_version", schema).unwrap();
}
