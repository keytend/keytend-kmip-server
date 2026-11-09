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

use std::{fs, time::Duration};

use kmip_protocol::client::{ClientCertificate, ConnectionSettings, tls::openssl::connect};
use kmip_protocol::types::common::{
    CryptographicAlgorithm, CryptographicUsageMask, KeyMaterial, ObjectType,
};
use kmip_protocol::types::request::{Attribute, RequestPayload, TemplateAttribute};
use kmip_protocol::types::response::{ManagedObject, ResponsePayload};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pki = std::env::var("KMIP_PKI")?; // the quick start's test certificates
    // KMIP_CLIENT picks the certificate in KMIP_PKI: client, other or unlisted.
    let name = std::env::var("KMIP_CLIENT").unwrap_or_else(|_| "client".into());
    let client = connect(&ConnectionSettings {
        host: "127.0.0.1".into(), // must match the server certificate (IP or DNS name)
        port: 5696,
        ca_cert: Some(fs::read(format!("{pki}/ca.pem"))?),
        client_cert: Some(ClientCertificate::SeparatePem {
            cert_bytes: fs::read(format!("{pki}/{name}.pem"))?,
            key_bytes: Some(fs::read(format!("{pki}/{name}.key"))?),
        }),
        connect_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(10)),
        write_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    })?;

    let ResponsePayload::Create(created) = client.do_request(RequestPayload::Create(
        ObjectType::SymmetricKey,
        TemplateAttribute::unnamed(vec![
            Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
            Attribute::CryptographicLength(256),
            Attribute::CryptographicUsageMask(CryptographicUsageMask::Encrypt),
        ]),
    ))?
    else {
        return Err("unexpected Create response".into());
    };
    let id = created.unique_identifier.0;
    client.activate_key(&id)?;
    let got = client.get_key(&id)?;
    let ManagedObject::SymmetricKey(key) = got.cryptographic_object else {
        return Err("expected a symmetric key".into());
    };
    let KeyMaterial::Bytes(bytes) = key.key_block.key_value.key_material else {
        return Err("expected raw key bytes".into());
    };
    println!("created {id}: {}-byte AES key", bytes.len());

    // Retire the key: an Active key is revoked before it can be destroyed.
    client.revoke_key(&id)?;
    client.destroy_key(&id)?;
    match client.get_key(&id) {
        Err(e) if e.is_connection_error() => return Err(e.into()),
        Err(e) => println!("Get after Destroy: {e}"), // the KMIP failure
        Ok(_) => return Err("destroyed key was returned".into()),
    }
    Ok(())
}
