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

//! Use the released SDK's public builders, codec, transport and typed responses.
use aes::{
    Aes256,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use kmip::{
    CryptographicUsageMask, Error,
    attributes::{AttributeName, AttributeValue},
    client::Client,
    enums::{
        CryptographicAlgorithm, KeyFormatType, PaddingMethod, ResultReason, ResultStatus,
        RevocationReasonCode, State,
    },
    interop::FormatSymmetric,
    payloads::GetAttributesResponsePayload,
    types::{CryptographicParameters, ProtocolVersion},
};
use serde_json::json;
use std::{path::Path, time::Duration};

fn pass(name: &str) {
    println!("{}", json!({"check": name, "status": "passed"}));
}

fn connect(
    pki: &Path,
    addr: &str,
    version: ProtocolVersion,
    identity: Option<&str>,
    ca: &str,
    domain: &str,
) -> kmip::Result<Client> {
    let mut builder = Client::builder()
        .add_root_certificate_file(pki.join(ca))?
        .with_version(version)
        .connect_timeout(Some(Duration::from_secs(3)))?
        .read_timeout(Some(Duration::from_secs(3)))?
        .write_timeout(Some(Duration::from_secs(3)))?;
    if let Some(identity) = identity {
        builder = builder.identity_file(
            pki.join(format!("{identity}.pem")),
            pki.join(format!("{identity}.key")),
        )?;
    }
    builder.connect(addr, domain)
}

fn refused<T>(result: kmip::Result<T>, reason: ResultReason, name: &str) {
    match result {
        Err(Error::KMIP(e))
            if e.status == ResultStatus::OperationFailed && e.reason == Some(reason) =>
        {
            pass(name)
        }
        Err(e) => panic!("{name}: wrong refusal: {e:?}"),
        Ok(_) => panic!("{name}: operation unexpectedly succeeded"),
    }
}

fn attr(response: &GetAttributesResponsePayload, name: AttributeName) -> &AttributeValue {
    &response
        .get_attribute_by_name(name)
        .expect("requested attribute absent")
        .value
}

fn state(client: &mut Client, id: &str, want: State) -> kmip::Result<()> {
    let response = client
        .get_attributes(id)
        .with_attribute(AttributeName::State)
        .exec()?;
    assert_eq!(response.unique_identifier, id);
    assert!(
        matches!(attr(&response, AttributeName::State), AttributeValue::State(s) if *s == want)
    );
    Ok(())
}

fn crypto(
    client: &mut Client,
    id: &str,
    key: &[u8],
    minor: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let input = [0x39u8; 32];
    let cipher = Aes256::new_from_slice(key).expect("AES-256 length already checked");
    let mut expected = input;
    for block in expected.as_chunks_mut::<16>().0 {
        cipher.encrypt_block(block.into());
    }
    let params = CryptographicParameters::aes_ecb(Some(PaddingMethod::None));
    let encrypted = client
        .encrypt(id)
        .data(input)
        .with_cryptographic_parameters(params.clone())
        .exec()?;
    assert_eq!(encrypted.unique_identifier, id);
    assert!(encrypted.data.as_deref() == Some(expected.as_slice()));
    let decrypted = client
        .decrypt(id)
        .data(expected)
        .with_cryptographic_parameters(params)
        .exec()?;
    assert!(decrypted.data.as_deref() == Some(input.as_slice()));
    pass("AES-256 ECB ciphertext matches independent RustCrypto; SDK decrypt exact plaintext");
    let iv = [0x42u8; 16];
    let mut params = CryptographicParameters::aes_cbc(Some(PaddingMethod::None));
    assert_eq!(params.iv_length, Some(16));
    refused(
        client
            .encrypt(id)
            .data(input)
            .with_iv_counter_nonce(iv)
            .with_cryptographic_parameters(params.clone())
            .exec(),
        ResultReason::InvalidField,
        "released aes_cbc helper reproduces IV Length unit mismatch",
    );
    println!(
        "{}",
        json!({"check":"aes_cbc helper IV units", "status":"known_sdk_helper_defect", "observed_iv_length":16, "required_bits":128})
    );
    params.iv_length = Some(128);
    let mut expected_cbc = input;
    let mut previous = iv;
    for block in expected_cbc.as_chunks_mut::<16>().0 {
        for (byte, preceding) in block.iter_mut().zip(previous) {
            *byte ^= preceding;
        }
        cipher.encrypt_block(block.into());
        previous.copy_from_slice(block);
    }
    let encrypted = client
        .encrypt(id)
        .data(input)
        .with_iv_counter_nonce(iv)
        .with_cryptographic_parameters(params.clone())
        .exec()?;
    assert!(encrypted.data.as_deref() == Some(expected_cbc.as_slice()));
    let decrypted = client
        .decrypt(id)
        .data(expected_cbc)
        .with_iv_counter_nonce(iv)
        .with_cryptographic_parameters(params)
        .exec()?;
    assert!(decrypted.data.as_deref() == Some(input.as_slice()));
    pass("explicit public CBC IV Length 128 bits matches independent RustCrypto CBC");
    if minor == 4 {
        let iv = [0x24u8; 12];
        let aad = [0x5au8; 13];
        let mut params = CryptographicParameters::aes_gcm(None, None);
        assert_eq!(params.iv_length, Some(12));
        refused(
            client
                .encrypt(id)
                .data(input)
                .with_iv_counter_nonce(iv)
                .with_cryptographic_parameters(params.clone())
                .exec(),
            ResultReason::InvalidField,
            "released aes_gcm helper reproduces IV Length unit mismatch",
        );
        println!(
            "{}",
            json!({"check":"aes_gcm helper IV units", "status":"known_sdk_helper_defect", "observed_iv_length":12, "required_bits":96})
        );
        params.iv_length = Some(96);
        let encrypted = client
            .encrypt(id)
            .data(input)
            .with_iv_counter_nonce(iv)
            .with_aad(aad)
            .with_cryptographic_parameters(params.clone())
            .exec()?;
        let tag = encrypted.authenticated_encryption_tag.expect("GCM tag");
        assert_eq!(tag.len(), 16);
        let ciphertext = encrypted.data.expect("GCM ciphertext");
        let decrypted = client
            .decrypt(id)
            .data(ciphertext.clone())
            .with_iv_counter_nonce(iv)
            .with_aad(aad)
            .with_tag(tag.clone())
            .with_cryptographic_parameters(params.clone())
            .exec()?;
        assert!(decrypted.data.as_deref() == Some(input.as_slice()));
        let mut corrupt = tag;
        corrupt[0] ^= 1;
        refused(
            client
                .decrypt(id)
                .data(ciphertext)
                .with_iv_counter_nonce(iv)
                .with_aad(aad)
                .with_tag(corrupt)
                .with_cryptographic_parameters(params)
                .exec(),
            ResultReason::CryptographicFailure,
            "GCM corrupted tag refused",
        );
        pass(
            "explicit public GCM IV Length 96 bits and AAD round trip; no independent GCM oracle claim",
        );
    }
    Ok(())
}

fn run(
    pki: &Path,
    addr: &str,
    version: ProtocolVersion,
    minor: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect(pki, addr, version, Some("client"), "ca.pem", "localhost")?;
    assert_eq!(client.version()?, version);
    let usage = CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt;
    let created = client.create().aes(256, usage).exec()?;
    let id = created.unique_identifier;
    assert!(!id.is_empty());
    state(&mut client, &id, State::PreActive)?;
    let first = client.get(&id).with_key_format(KeyFormatType::Raw).exec()?;
    assert_eq!(first.unique_identifier, id);
    let material = first.symmetric_key()?.to_vec();
    assert_eq!(material.len(), 32);
    let second = client.get(&id).with_key_format(KeyFormatType::Raw).exec()?;
    assert!(second.symmetric_key()? == material);
    pass("Create AES-256, PreActive state and repeated exact raw key Get");
    let response = client
        .get_attributes(&id)
        .with_attributes([
            AttributeName::CryptographicAlgorithm,
            AttributeName::CryptographicLength,
            AttributeName::CryptographicUsageMask,
            AttributeName::State,
        ])
        .exec()?;
    assert_eq!(response.unique_identifier, id);
    assert_eq!(response.attribute.len(), 4);
    assert!(matches!(
        attr(&response, AttributeName::CryptographicAlgorithm),
        AttributeValue::CryptographicAlgorithm(CryptographicAlgorithm::AES)
    ));
    assert!(
        matches!(attr(&response, AttributeName::CryptographicLength), AttributeValue::CryptographicLength(n) if n.0 == 256)
    );
    assert!(
        matches!(attr(&response, AttributeName::CryptographicUsageMask), AttributeValue::CryptographicUsageMask(m) if *m == usage)
    );
    pass("SDK typed attributes preserve AES, length, usage and state");
    client.activate(&id).exec()?;
    state(&mut client, &id, State::Active)?;
    let activated = client.get(&id).with_key_format(KeyFormatType::Raw).exec()?;
    assert!(activated.symmetric_key()? == material);
    pass("Activate changes state and preserves exact key");
    refused(
        client.get("phsym-missing-object").exec(),
        ResultReason::ItemNotFound,
        "missing object typed ItemNotFound",
    );
    let mut other = connect(pki, addr, version, Some("other"), "ca.pem", "localhost")?;
    refused(
        other.get(&id).exec(),
        ResultReason::ItemNotFound,
        "other authorized principal cannot read owner key",
    );
    refused(
        other.create().aes(256, usage).exec(),
        ResultReason::PermissionDenied,
        "read-only principal cannot Create",
    );
    let mut unlisted = connect(pki, addr, version, Some("unlisted"), "ca.pem", "localhost")?;
    refused(
        unlisted.get(&id).exec(),
        ResultReason::PermissionDenied,
        "CA-valid unlisted certificate denied by policy",
    );

    if minor >= 2 {
        crypto(&mut client, &id, &material, minor)?;
        // NIST SP 800-38A F.1.5 AES-256 ECB first block, through public Register.
        let known_key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1,
            0x81, 0xf8,
        ];
        let known = client
            .register()
            .symmetric_key(
                known_key,
                CryptographicAlgorithm::AES,
                FormatSymmetric::Raw,
                usage,
            )?
            .exec()?
            .unique_identifier;
        let recovered = client
            .get(&known)
            .with_key_format(KeyFormatType::Raw)
            .exec()?;
        assert!(recovered.symmetric_key()? == known_key);
        client.activate(&known).exec()?;
        let result = client
            .encrypt(&known)
            .data(plaintext)
            .with_cryptographic_parameters(CryptographicParameters::aes_ecb(Some(
                PaddingMethod::None,
            )))
            .exec()?;
        assert!(result.data.as_deref() == Some(expected.as_slice()));
        client
            .revoke(&known)
            .with_revocation_reason_code(RevocationReasonCode::CessationOfOperation)
            .exec()?;
        client.destroy(&known).exec()?;
        refused(
            client.get(&known).exec(),
            ResultReason::IllegalOperation,
            "destroyed known-answer key unavailable",
        );
        pass("public Register and NIST AES-256 ECB known answer");
    } else {
        println!(
            "{}",
            json!({"check":"Encrypt/Decrypt", "status":"unsupported", "reason":"KMIP cryptographic services introduced in 1.2"})
        );
    }
    client
        .revoke(&id)
        .with_revocation_reason_code(RevocationReasonCode::CessationOfOperation)
        .exec()?;
    state(&mut client, &id, State::Deactivated)?;
    if minor >= 2 {
        refused(
            client
                .encrypt(&id)
                .data([0u8; 16])
                .with_cryptographic_parameters(CryptographicParameters::aes_ecb(Some(
                    PaddingMethod::None,
                )))
                .exec(),
            ResultReason::PermissionDenied,
            "revoked key cannot Encrypt",
        );
    }
    client.destroy(&id).exec()?;
    state(&mut client, &id, State::Destroyed)?;
    refused(
        client.get(&id).exec(),
        ResultReason::IllegalOperation,
        "destroyed generated key unavailable",
    );
    pass("Revoke Deactivated and Destroy Destroyed state transitions");

    for (name, identity, ca, domain, expected_text) in [
        (
            "wrong server trust anchor",
            Some("client"),
            "wrong-ca.pem",
            "localhost",
            "UnknownIssuer",
        ),
        (
            "wrong server hostname",
            Some("client"),
            "ca.pem",
            "wrong.invalid",
            "NotValidForName",
        ),
        (
            "missing client certificate",
            None,
            "ca.pem",
            "localhost",
            "CertificateRequired",
        ),
        (
            "untrusted client certificate",
            Some("untrusted"),
            "ca.pem",
            "localhost",
            "UnknownCA",
        ),
    ] {
        let result = connect(pki, addr, version, identity, ca, domain)
            .and_then(|mut c| c.get("phsym-negative-probe").exec());
        match result {
            Err(error) => {
                let debug = format!("{error:?}");
                assert!(
                    !matches!(error, Error::KMIP(_)),
                    "{name}: protocol denial is not a TLS trust failure"
                );
                assert!(
                    debug.contains(expected_text),
                    "{name}: unexpected error: {debug}"
                );
                println!(
                    "{}",
                    json!({"check":name,"status":"passed","observed_error":debug})
                );
            }
            Ok(_) => panic!("{name}: unexpectedly accepted"),
        }
    }
    // A successful fresh owner request distinguishes negatives from fixture outage.
    let mut fresh = connect(pki, addr, version, Some("client"), "ca.pem", "localhost")?;
    refused(
        fresh.get("phsym-final-probe").exec(),
        ResultReason::ItemNotFound,
        "owner remains usable after trust/identity negatives",
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 4, "usage: adapter PKI-DIR HOST:PORT MINOR");
    let minor: u8 = args[3].parse()?;
    let version = match minor {
        0 => ProtocolVersion::V1_0,
        1 => ProtocolVersion::V1_1,
        2 => ProtocolVersion::V1_2,
        3 => ProtocolVersion::V1_3,
        4 => ProtocolVersion::V1_4,
        _ => panic!("unsupported edition"),
    };
    run(Path::new(&args[1]), &args[2], version, minor)
}
