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

//! Provisioning records (docs/re-provision.md) are hidden objects of the
//! store: `check-store` verifies them, `backup` copies them, in-place
//! master-key rotation re-seals them, and `restore` brings back the state of
//! the backup, which can revive a retired certificate
//! (docs/backup-restore.md).
use keytend_kmip_server::{
    protocol::{Channel, Engine, Lookup, Provisioning, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};
use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        X509, X509NameBuilder, X509ReqBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    },
};
use std::{
    collections::HashSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

const BIN: &str = env!("CARGO_BIN_EXE_keytend-kmip-server");

fn key() -> PKey<Private> {
    PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap()
}
fn certificate(cn: &str, key: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(issuer.map_or(&*name, |(ca, _)| ca.subject_name()))
        .unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    if issuer.is_none() {
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(KeyUsage::new().key_cert_sign().build().unwrap())
            .unwrap();
    } else {
        b.append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
            .unwrap();
    }
    b.sign(issuer.map_or(key, |(_, k)| k), MessageDigest::sha256())
        .unwrap();
    b.build()
}
fn fingerprint(cert: &X509) -> String {
    hex::encode(cert.digest(MessageDigest::sha256()).unwrap())
}
fn private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn cli(args: &[&dyn AsRef<std::ffi::OsStr>]) -> Output {
    let output = Command::new(BIN)
        .args(args.iter().map(|a| a.as_ref()))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn lookup(database: &Path, master: &Path, cert: &X509) -> Lookup {
    Engine::new(Store::open(database, master).unwrap(), false)
        .provisioned_lookup(&fingerprint(cert))
        .unwrap()
}

#[test]
fn provisioning_records_survive_check_backup_rotation_and_restore() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let data = d.join("data");
    fs::create_dir(&data).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    let database = data.join("kmip.sqlite");
    let (old_master, new_master) = (d.join("old.key"), d.join("new.key"));
    private(&old_master, &[0x31; 32]);
    private(&new_master, &[0x57; 32]);
    let ca_key = key();
    let ca = certificate("provisioning", &ca_key, None);
    fs::write(d.join("ca.pem"), ca.to_pem().unwrap()).unwrap();
    private(
        &d.join("ca.key"),
        &ca_key.private_key_to_pem_pkcs8().unwrap(),
    );
    let f = certificate("client", &key(), Some((&ca, &ca_key)));
    // A backup from before the Re-Provision.
    drop(Store::open(&database, &old_master).unwrap());
    let before = d.join("before.sqlite");
    cli(&[
        &"backup",
        &"--database",
        &database,
        &"--master-key",
        &old_master,
        &"--output",
        &before,
    ]);
    // Re-Provision F with a certificate request.
    let provisioning = Provisioning::load(
        &d.join("ca.pem"),
        &d.join("ca.key"),
        Box::new(|_: &X509, _: &[X509]| Ok(())),
        HashSet::new(),
    )
    .unwrap();
    let mut engine = Engine::new(Store::open(&database, &old_master).unwrap(), false)
        .with_provisioning(provisioning);
    let new_key = key();
    let mut csr = X509ReqBuilder::new().unwrap();
    csr.set_pubkey(&new_key).unwrap();
    csr.sign(&new_key, MessageDigest::sha256()).unwrap();
    let v = Version(2, 1);
    let message = Node::structure(
        REQUEST_MESSAGE,
        vec![
            Node::structure(REQUEST_HEADER, vec![v.node(), Node::int(BATCH_COUNT, 2)]),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, 53),
                    Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![0]),
                    Node::structure(
                        REQUEST_PAYLOAD,
                        vec![Node::structure(
                            CERTIFICATE_REQUEST,
                            vec![
                                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                                Node::bytes(
                                    CERTIFICATE_REQUEST_VALUE,
                                    csr.build().to_der().unwrap(),
                                ),
                            ],
                        )],
                    ),
                ],
            ),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, 10),
                    Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![1]),
                    Node::structure(REQUEST_PAYLOAD, vec![]),
                ],
            ),
        ],
    );
    let channel = Channel {
        fingerprint: fingerprint(&f),
        policy_fingerprint: fingerprint(&f),
        certificate: f.to_der().unwrap(),
        chain: vec![],
    };
    let response = engine
        .with_channel(&channel, |e| {
            e.process_with_grants("alice", &message, Some(&[10, 53]), &[])
        })
        .unwrap();
    let value = response
        .all(BATCH_ITEM)
        .nth(1)
        .unwrap()
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(CERTIFICATE)
        .unwrap()
        .required(CERTIFICATE_VALUE)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec();
    let n = X509::from_der(&value).unwrap();
    drop(engine);
    assert_eq!(lookup(&database, &old_master, &f), Lookup::Retired);
    // check-store authenticates the records with every other object.
    let out = cli(&[
        &"check-store",
        &"--database",
        &database,
        &"--master-key",
        &old_master,
    ]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("object records and audit chain verified"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    // backup copies them.
    let after = d.join("after.sqlite");
    cli(&[
        &"backup",
        &"--database",
        &database,
        &"--master-key",
        &old_master,
        &"--output",
        &after,
    ]);
    assert_eq!(lookup(&after, &old_master, &f), Lookup::Retired);
    // In-place master-key rotation re-seals them.
    cli(&[
        &"rotate-master-key",
        &"--in-place",
        &"--database",
        &database,
        &"--master-key",
        &new_master,
        &"--previous-master-key",
        &old_master,
    ]);
    assert_eq!(lookup(&database, &new_master, &f), Lookup::Retired);
    assert_eq!(
        lookup(&database, &new_master, &n),
        Lookup::Replacement {
            policy_fingerprint: fingerprint(&f),
            principal: "alice".into()
        }
    );
    cli(&[
        &"check-store",
        &"--database",
        &database,
        &"--master-key",
        &new_master,
    ]);
    // Restoring a backup from before the Re-Provision brings back its
    // state: F is no longer retired and N is unknown again.
    cli(&[
        &"restore",
        &"--from",
        &before,
        &"--id",
        &"before-re-provision",
        &"--database",
        &database,
        &"--master-key",
        &old_master,
    ]);
    assert_eq!(lookup(&database, &old_master, &f), Lookup::Unknown);
    assert_eq!(lookup(&database, &old_master, &n), Lookup::Unknown);
}
