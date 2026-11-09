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

use kmip_protocol::client::{
    tls::openssl::{connect, connect_with_tcp_stream_factory},
    Client, ClientCertificate, ConnectionSettings, Error,
};
use kmip_protocol::types::common::{
    AttributeName, AttributeValue, CryptographicAlgorithm, CryptographicUsageMask, KeyMaterial,
    ObjectType, State, UniqueIdentifier,
};
use kmip_protocol::types::request::{self, RequestPayload, TemplateAttribute};
use kmip_protocol::types::response::{ManagedObject, ResponsePayload};
use openssl::{asn1::Asn1Time, bn::BigNum, hash::MessageDigest, pkey::PKey, rsa::Rsa, x509};
use std::{
    fs,
    net::TcpStream,
    path::{Path, PathBuf},
    time::Duration,
};

type R<T> = Result<T, Box<dyn std::error::Error>>;

fn settings(p: &Path, identity: Option<&str>, ca: Vec<u8>) -> R<ConnectionSettings> {
    Ok(ConnectionSettings {
        host: "127.0.0.1".into(),
        port: std::env::var("KMIP_PORT")
            .unwrap_or("15696".into())
            .parse()?,
        ca_cert: Some(ca),
        client_cert: match identity {
            Some(name) => Some(ClientCertificate::SeparatePem {
                cert_bytes: fs::read(p.join(format!("{name}.pem")))?,
                key_bytes: Some(fs::read(p.join(format!("{name}.key")))?),
            }),
            None => None,
        },
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(10)),
        write_timeout: Some(Duration::from_secs(10)),
        max_response_bytes: Some(1024 * 1024),
        ..Default::default()
    })
}

/// A self-signed certificate and key that no configured trust store contains.
fn self_signed(cn: &str, ca: bool) -> R<(Vec<u8>, Vec<u8>)> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = x509::X509NameBuilder::new()?;
    name.append_entry_by_text("CN", cn)?;
    let name = name.build();
    let mut b = x509::X509Builder::new()?;
    b.set_version(2)?;
    let serial = BigNum::from_u32(7)?.to_asn1_integer()?;
    b.set_serial_number(&serial)?;
    b.set_subject_name(&name)?;
    b.set_issuer_name(&name)?;
    b.set_pubkey(&key)?;
    let (start, end) = (Asn1Time::days_from_now(0)?, Asn1Time::days_from_now(1)?);
    b.set_not_before(&start)?;
    b.set_not_after(&end)?;
    let mut constraints = x509::extension::BasicConstraints::new();
    if ca {
        constraints.critical().ca();
    }
    b.append_extension(constraints.build()?)?;
    if !ca {
        b.append_extension(
            x509::extension::ExtendedKeyUsage::new()
                .client_auth()
                .build()?,
        )?;
    }
    b.sign(&key, MessageDigest::sha256())?;
    Ok((b.build().to_pem()?, key.private_key_to_pem_pkcs8()?))
}

fn state(c: &Client<openssl::ssl::SslStream<TcpStream>>, id: &str) -> R<(State, Option<i32>)> {
    let response = c.do_request(RequestPayload::GetAttributes(
        Some(UniqueIdentifier(id.into())),
        Some(vec![
            AttributeName("State".into()),
            AttributeName("Cryptographic Length".into()),
        ]),
    ))?;
    let ResponsePayload::GetAttributes(payload) = response else {
        panic!("expected Get Attributes payload")
    };
    let (mut found, mut length) = (None, None);
    for a in payload.attributes.unwrap_or_default() {
        match (a.name.0.as_str(), a.value) {
            ("State", AttributeValue::State(s)) => found = Some(s),
            ("Cryptographic Length", AttributeValue::Integer(n)) => length = Some(n),
            _ => {}
        }
    }
    Ok((found.expect("State attribute"), length))
}

fn material(c: &Client<openssl::ssl::SslStream<TcpStream>>, id: &str) -> R<Vec<u8>> {
    match c.get_key(id)?.cryptographic_object {
        ManagedObject::SymmetricKey(k) => match k.key_block.key_value.key_material {
            KeyMaterial::Bytes(bytes) => Ok(bytes),
            other => panic!("expected raw symmetric key bytes, got {other:?}"),
        },
        other => panic!("expected a symmetric key, got {other:?}"),
    }
}

/// A TLS-layer refusal: either the handshake fails, or the server's post-handshake
/// alert (TLS 1.3 client authentication) fails the first request. Never a KMIP reply.
fn refused<T: std::fmt::Debug>(label: &str, result: Result<T, Error>) -> String {
    match result {
        Ok(v) => panic!("{label}: accepted ({v:?})"),
        Err(Error::ServerError(m) | Error::ItemNotFound(m)) if m.contains("Operation") => {
            panic!("{label}: refused at the KMIP layer instead of TLS: {m}")
        }
        Err(e) => format!("{e}"),
    }
}

fn main() -> R<()> {
    let p = PathBuf::from(std::env::var("KMIP_PKI")?);
    let ca = fs::read(p.join("ca.pem"))?;
    let c = connect(&settings(&p, Some("client"), ca.clone())?)?;
    let q = c.query()?;
    assert_eq!(q.vendor_identification.as_deref(), Some("keytend-kmip-server"));
    let (private, public) =
        c.create_rsa_key_pair(2048, "nlnet-private".into(), "nlnet-public".into())?;
    c.activate_key(&private)?;
    let sig = c.sign(&private, b"database signing test")?;
    assert_eq!(sig.signature_data.len(), 256);
    let exported = c.get_key(&private)?;
    if let ManagedObject::PrivateKey(k) = exported.cryptographic_object {
        let KeyMaterial::Bytes(der) = k.key_block.key_value.key_material else {
            panic!("expected PKCS8 byte string")
        };
        let pubkey = PKey::private_key_from_pkcs8(&der)?;
        let mut verify = openssl::sign::Verifier::new(MessageDigest::sha256(), &pubkey)?;
        verify.update(b"database signing test")?;
        assert!(verify.verify(&sig.signature_data)?);
    } else {
        panic!("expected RSA private key");
    }
    assert_eq!(c.rng_retrieve(32)?.data.len(), 32);
    c.destroy_key(&public)?;
    c.revoke_key(&private)?;
    c.destroy_key(&private)?;
    println!("PASS NLnetLabs: Query, CreateKeyPair, Activate, Sign, RNGRetrieve, Revoke, Destroy");

    // Symmetric lifecycle through the public request/response types.
    let created = c.do_request(RequestPayload::Create(
        ObjectType::SymmetricKey,
        TemplateAttribute::unnamed(vec![
            request::Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
            request::Attribute::CryptographicLength(256),
            request::Attribute::CryptographicUsageMask(CryptographicUsageMask::Encrypt),
        ]),
    ))?;
    let ResponsePayload::Create(created) = created else {
        panic!("expected Create payload")
    };
    let id = created.unique_identifier.0;
    assert_eq!(state(&c, &id)?, (State::PreActive, Some(256)));
    c.activate_key(&id)?;
    assert_eq!(state(&c, &id)?.0, State::Active);
    let first = material(&c, &id)?;
    assert_eq!(first.len(), 32);
    assert_eq!(
        material(&c, &id)?,
        first,
        "repeated Get changed the material"
    );
    c.revoke_key(&id)?;
    assert_eq!(state(&c, &id)?.0, State::Deactivated);
    c.destroy_key(&id)?;
    assert_eq!(state(&c, &id)?.0, State::Destroyed);
    let destroyed = c
        .get_key(&id)
        .expect_err("Get after Destroy returned material");
    assert!(
        matches!(&destroyed, Error::ServerError(m) | Error::ItemNotFound(m) if m.contains("Get")),
        "{destroyed:?}"
    );
    let missing = c
        .get_key("keytend-nlnet-missing-object")
        .expect_err("missing object returned");
    assert!(matches!(missing, Error::ItemNotFound(_)), "{missing:?}");
    println!("PASS NLnetLabs: AES-256 Create, typed PreActive/Active/Deactivated/Destroyed state and length, repeated exact 32-byte Get, refusal after Destroy ({destroyed}), missing object ItemNotFound");

    // Principal and operation ACLs (scripts/dev-pki.sh policy).
    let owned = c.do_request(RequestPayload::Create(
        ObjectType::SymmetricKey,
        TemplateAttribute::unnamed(vec![
            request::Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
            request::Attribute::CryptographicLength(256),
            request::Attribute::CryptographicUsageMask(CryptographicUsageMask::Encrypt),
        ]),
    ))?;
    let ResponsePayload::Create(owned) = owned else {
        panic!("expected Create payload")
    };
    let owned = owned.unique_identifier.0;
    c.activate_key(&owned)?;
    let other = connect(&settings(&p, Some("other"), ca.clone())?)?;
    let hidden = other
        .get_key(&owned)
        .expect_err("other principal read the key");
    assert!(matches!(hidden, Error::ItemNotFound(_)), "{hidden:?}");
    let create = other
        .do_request(RequestPayload::Create(
            ObjectType::SymmetricKey,
            TemplateAttribute::unnamed(vec![
                request::Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                request::Attribute::CryptographicLength(256),
            ]),
        ))
        .expect_err("read-only principal created a key");
    assert!(
        matches!(&create, Error::ServerError(m) if m.contains("denied")),
        "{create:?}"
    );
    let unlisted = connect(&settings(&p, Some("unlisted"), ca.clone())?)?;
    let query = unlisted.query().expect_err("unlisted certificate queried");
    assert!(
        matches!(&query, Error::ServerError(m) if m.contains("denied")),
        "{query:?}"
    );
    println!("PASS NLnetLabs: other principal Get is ItemNotFound, read-only Create denied, CA-valid unlisted certificate denied");

    // Trust, hostname and identity negatives, each followed by a fresh good request.
    let (wrong_ca, _) = self_signed("nlnet-wrong-ca", true)?;
    let e = refused(
        "wrong server CA",
        connect(&settings(&p, Some("client"), wrong_ca)?).and_then(|c| c.query()),
    );
    assert!(e.contains("certificate verify failed"), "{e}");
    let port: u16 = std::env::var("KMIP_PORT")?.parse()?;
    let mut wrong_name = settings(&p, Some("client"), ca.clone())?;
    // The SDK verifies the name it was given; the address is not in the server SAN.
    wrong_name.host = "127.0.0.2".into();
    let e = refused(
        "wrong hostname",
        connect_with_tcp_stream_factory(&wrong_name, |_, _| {
            Ok(TcpStream::connect(("127.0.0.1", port))?)
        })
        .and_then(|c| c.query()),
    );
    assert!(
        e.contains("certificate verify failed") && e.contains("mismatch"),
        "{e}"
    );
    let e = refused(
        "missing client certificate",
        connect(&settings(&p, None, ca.clone())?).and_then(|c| c.query()),
    );
    let missing_cert = e;
    let (cert, key) = self_signed("client", false)?;
    let mut untrusted = settings(&p, None, ca.clone())?;
    untrusted.client_cert = Some(ClientCertificate::SeparatePem {
        cert_bytes: cert,
        key_bytes: Some(key),
    });
    let untrusted_error = refused(
        "untrusted client certificate",
        connect(&untrusted).and_then(|c| c.query()),
    );
    let fresh = connect(&settings(&p, Some("client"), ca)?)?;
    assert_eq!(
        fresh.query()?.vendor_identification.as_deref(),
        Some("keytend-kmip-server")
    );
    assert_eq!(material(&fresh, &owned)?.len(), 32);
    println!("PASS NLnetLabs: wrong server CA and wrong hostname refused by SDK verification; missing ({missing_cert}) and untrusted ({untrusted_error}) client certificates refused; fresh authorized request succeeds");
    Ok(())
}
