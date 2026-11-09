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

use cosmian_kms_client::kmip_0::kmip_messages::{
    RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader, ResponseMessage,
    ResponseMessageBatchItemVersioned,
};
use cosmian_kms_client::kmip_0::kmip_types::{
    BlockCipherMode, CryptographicUsageMask, PaddingMethod, ResultStatusEnumeration,
    RevocationReason, RevocationReasonCode, State,
};
use cosmian_kms_client::kmip_2_1::{
    kmip_attributes::Attributes,
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_messages::RequestMessageBatchItem,
    kmip_objects::{Object, ObjectType, SymmetricKey},
    kmip_operations::*,
    kmip_types::*,
};
use cosmian_kms_client::{KmsClient, KmsClientConfig, http_client::HttpClientConfig};
use serde_json::{Value, json};
use std::{error::Error, path::Path};

/// NIST SP 800-38A section F.2.5, CBC-AES256.Encrypt: an AES known answer that
/// does not depend on any library under test.
const KAT_KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const KAT_IV: &str = "000102030405060708090a0b0c0d0e0f";
const KAT_PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const KAT_CIPHERTEXT: &str = "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b";

fn client(pki: &Path, port: &str, mode: &str) -> Result<KmsClient, Box<dyn Error>> {
    let identity = match mode {
        "other" => "other",
        "unlisted" => "unlisted",
        "untrusted" => "untrusted",
        _ => "client",
    };
    let ca = if mode == "wrong-ca" {
        "wrong-ca.pem"
    } else {
        "ca.pem"
    };
    let host = if mode == "wrong-host" {
        "127.0.0.1"
    } else {
        "localhost"
    };
    let mut http_config = HttpClientConfig {
        server_url: format!("https://{host}:{port}"),
        accept_invalid_certs: false,
        verified_cert: Some(std::fs::read_to_string(pki.join(ca))?),
        ..Default::default()
    };
    if mode != "no-identity" {
        http_config.tls_client_pem_cert_path =
            Some(pki.join(format!("{identity}.pem")).display().to_string());
        http_config.tls_client_pem_key_path =
            Some(pki.join(format!("{identity}.key")).display().to_string());
    }
    Ok(KmsClient::new_with_config(KmsClientConfig {
        http_config,
        print_json: Some(true),
        ..Default::default()
    })?)
}
fn aes_attributes() -> Attributes {
    Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        ..Default::default()
    }
}
fn create() -> Operation {
    Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: aes_attributes(),
        protection_storage_masks: None,
    })
}
fn uid(id: &str) -> Option<UniqueIdentifier> {
    Some(UniqueIdentifier::TextString(id.to_owned()))
}
fn get(id: &str) -> Operation {
    Operation::Get(Get {
        unique_identifier: uid(id),
        ..Default::default()
    })
}
fn cbc(padding: PaddingMethod) -> Option<CryptographicParameters> {
    Some(CryptographicParameters {
        block_cipher_mode: Some(BlockCipherMode::CBC),
        padding_method: Some(padding),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        ..Default::default()
    })
}
fn encrypt(id: &str, padding: PaddingMethod, iv: &[u8], data: &[u8]) -> Operation {
    Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: uid(id),
        cryptographic_parameters: cbc(padding),
        data: Some(data.to_vec().into()),
        i_v_counter_nonce: Some(iv.to_vec()),
        ..Default::default()
    }))
}
fn decrypt(id: &str, padding: PaddingMethod, iv: &[u8], data: &[u8]) -> Operation {
    Operation::Decrypt(Box::new(Decrypt {
        unique_identifier: uid(id),
        cryptographic_parameters: cbc(padding),
        data: Some(data.to_vec()),
        i_v_counter_nonce: Some(iv.to_vec()),
        ..Default::default()
    }))
}
fn revoke(id: &str) -> Operation {
    Operation::Revoke(Revoke {
        unique_identifier: uid(id),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::CessationOfOperation,
            revocation_message: Some("Cosmian SDK trial complete".to_owned()),
        },
        compromise_occurrence_date: None,
        cascade: false,
    })
}
fn destroy(id: &str) -> Operation {
    Operation::Destroy(Destroy {
        unique_identifier: uid(id),
        remove: false,
        cascade: false,
        expected_object_type: None,
    })
}
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("constant hex"))
        .collect()
}
async fn exchange(client: &KmsClient, op: Operation) -> Result<ResponseMessage, Box<dyn Error>> {
    let request = RequestMessage {
        request_header: RequestMessageHeader {
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem::new(op),
        )],
    };
    Ok(tokio::time::timeout(
        std::time::Duration::from_secs(20),
        client.post_message(&request),
    )
    .await??)
}
/// One SDK-decoded batch item: its result status, reason and payload.
struct Outcome {
    status: ResultStatusEnumeration,
    reason: Option<String>,
    payload: Option<Operation>,
}
/// Every step is one RequestMessage. A transport or decode error is reported
/// as an SDK error; a decoded KMIP failure is reported with its reason.
struct Trial {
    steps: Vec<Value>,
    /// RequestMessages sent so far; the SDK logs one response for each.
    exchanges: usize,
}
impl Trial {
    async fn run(&mut self, name: &str, client: &KmsClient, op: Operation) -> Option<Outcome> {
        self.exchanges += 1;
        match exchange(client, op).await {
            Ok(response) => {
                let item = match response.batch_item.as_slice() {
                    [ResponseMessageBatchItemVersioned::V21(item)] => item,
                    _ => {
                        self.record(name, "sdk_unexpected_shape", json!(format!("{response:?}")));
                        return None;
                    }
                };
                Some(Outcome {
                    status: item.result_status,
                    reason: item.result_reason.map(|r| format!("{r:?}")),
                    payload: item.response_payload.clone(),
                })
            }
            Err(error) => {
                self.record(
                    name,
                    "sdk_error",
                    json!({"error": error.to_string(), "error_debug": format!("{error:?}")}),
                );
                None
            }
        }
    }
    fn record(&mut self, name: &str, status: &str, detail: Value) {
        let step = json!({"event":"step", "step":name, "status":status, "detail":detail,
                          "exchange":self.exchanges});
        println!("{step}");
        self.steps.push(step);
    }
    /// Expect Success; return the payload for the step's own checks.
    async fn success(
        &mut self,
        name: &str,
        client: &KmsClient,
        op: Operation,
    ) -> Option<Operation> {
        let outcome = self.run(name, client, op).await?;
        if outcome.status != ResultStatusEnumeration::Success {
            self.record(
                name,
                "kmip_failure",
                json!({"result_status": format!("{:?}", outcome.status), "result_reason": outcome.reason}),
            );
            return None;
        }
        outcome.payload
    }
    /// Expect a decoded KMIP Operation Failed; record its reason.
    async fn refused(&mut self, name: &str, client: &KmsClient, op: Operation) {
        let Some(outcome) = self.run(name, client, op).await else {
            return;
        };
        let detail = json!({"result_status": format!("{:?}", outcome.status), "result_reason": outcome.reason});
        if outcome.status == ResultStatusEnumeration::OperationFailed {
            self.record(name, "refused", detail);
        } else {
            self.record(name, "unexpected_success", detail);
        }
    }
    fn check(&mut self, name: &str, ok: bool, detail: Value) {
        self.record(name, if ok { "passed" } else { "mismatch" }, detail);
    }
}
/// Length and equality of two SDK-decoded Get key values, compared without
/// copying the zeroizing buffers the SDK returns.
fn same_key(a: &Option<Operation>, b: &Option<Operation>) -> Option<(usize, bool)> {
    let bytes = |payload: &Option<Operation>| match payload {
        Some(Operation::GetResponse(GetResponse {
            object: Object::SymmetricKey(SymmetricKey { key_block }),
            ..
        })) => key_block.key_bytes().ok(),
        _ => None,
    };
    let (a, b) = (bytes(a)?, bytes(b)?);
    Some((a.len(), *a == *b))
}
fn raw_symmetric(key: &[u8]) -> Object {
    Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(key.to_vec().into()),
                attributes: None,
            }),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            key_wrapping_data: None,
        },
    })
}
/// The planned lifecycle: each check consumes only SDK-decoded values.
async fn lifecycle(c: &KmsClient, other: &KmsClient) -> Vec<Value> {
    let mut t = Trial {
        steps: vec![],
        exchanges: 0,
    };
    let id = match t.success("create", c, create()).await {
        Some(Operation::CreateResponse(r)) => r.unique_identifier.to_string(),
        other => {
            t.check("create", false, json!(format!("{other:?}")));
            return t.steps;
        }
    };
    t.check("create", true, json!({"object_type": "SymmetricKey"}));
    let activate = Operation::Activate(Activate {
        unique_identifier: UniqueIdentifier::TextString(id.clone()),
    });
    if let Some(r) = t.success("activate", c, activate).await {
        t.check(
            "activate",
            matches!(r, Operation::ActivateResponse(_)),
            json!(null),
        );
    }
    // Repeated Get returns the same 256-bit key material. Bytes are compared
    // here and never printed.
    let first = t.success("get-1", c, get(&id)).await;
    let second = t.success("get-2", c, get(&id)).await;
    if let Some((length, equal)) = same_key(&first, &second) {
        t.check(
            "get-exact",
            length == 32 && equal,
            json!({"length": length, "equal": equal}),
        );
    } else {
        t.check(
            "get-exact",
            false,
            json!("key bytes unavailable from SDK-decoded Get"),
        );
    }
    let refs = [
        Tag::State,
        Tag::CryptographicAlgorithm,
        Tag::CryptographicLength,
        Tag::CryptographicUsageMask,
        Tag::ObjectType,
    ];
    let selected = Operation::GetAttributes(GetAttributes {
        unique_identifier: uid(&id),
        attribute_reference: Some(refs.into_iter().map(AttributeReference::Standard).collect()),
    });
    if let Some(Operation::GetAttributesResponse(r)) =
        t.success("get-attributes", c, selected).await
    {
        let a = &r.attributes;
        let mask = CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt;
        t.check(
            "get-attributes",
            a.state == Some(State::Active)
                && a.cryptographic_algorithm == Some(CryptographicAlgorithm::AES)
                && a.cryptographic_length == Some(256)
                && a.cryptographic_usage_mask == Some(mask)
                && a.object_type == Some(ObjectType::SymmetricKey),
            json!({"state": format!("{:?}", a.state), "algorithm": format!("{:?}", a.cryptographic_algorithm),
                   "length": a.cryptographic_length, "usage_mask": format!("{:?}", a.cryptographic_usage_mask),
                   "object_type": format!("{:?}", a.object_type)}),
        );
    }
    let all = Operation::GetAttributes(GetAttributes {
        unique_identifier: uid(&id),
        attribute_reference: None,
    });
    if let Some(Operation::GetAttributesResponse(r)) = t.success("get-all-attributes", c, all).await
    {
        t.check(
            "get-all-attributes",
            r.attributes.state == Some(State::Active),
            json!({"state": format!("{:?}", r.attributes.state)}),
        );
    }
    // Encrypt/Decrypt round trip with the created key (CBC, PKCS#5 padding).
    let message = b"Cosmian SDK trial 2026-10-31";
    let iv = [0x25u8; 16];
    if let Some(Operation::EncryptResponse(r)) = t
        .success(
            "encrypt",
            c,
            encrypt(&id, PaddingMethod::PKCS5, &iv, message),
        )
        .await
    {
        let data = r.data.unwrap_or_default();
        t.check(
            "encrypt",
            data.len() == 32 && data != message,
            json!({"length": data.len()}),
        );
        if let Some(Operation::DecryptResponse(d)) = t
            .success("decrypt", c, decrypt(&id, PaddingMethod::PKCS5, &iv, &data))
            .await
        {
            let plain = d.data.map(|p| p.to_vec()).unwrap_or_default();
            t.check("decrypt", plain == message, json!({"length": plain.len()}));
        }
    }
    // AES known answer: register the published NIST key, then encrypt and
    // decrypt the published blocks without padding.
    let register = Operation::Register(Box::new(Register {
        object_type: ObjectType::SymmetricKey,
        attributes: aes_attributes(),
        object: raw_symmetric(&hex(KAT_KEY)),
        protection_storage_masks: None,
    }));
    if let Some(Operation::RegisterResponse(r)) = t.success("kat-register", c, register).await {
        let kat = r.unique_identifier.to_string();
        let activate = Operation::Activate(Activate {
            unique_identifier: UniqueIdentifier::TextString(kat.clone()),
        });
        t.success("kat-activate", c, activate).await;
        let (iv, plain, cipher) = (hex(KAT_IV), hex(KAT_PLAINTEXT), hex(KAT_CIPHERTEXT));
        if let Some(Operation::EncryptResponse(e)) = t
            .success(
                "kat-encrypt",
                c,
                encrypt(&kat, PaddingMethod::None, &iv, &plain),
            )
            .await
        {
            let data = e.data.unwrap_or_default();
            t.check(
                "kat-encrypt",
                data == cipher,
                json!({"expected": KAT_CIPHERTEXT, "equal": data == cipher}),
            );
        }
        if let Some(Operation::DecryptResponse(d)) = t
            .success(
                "kat-decrypt",
                c,
                decrypt(&kat, PaddingMethod::None, &iv, &cipher),
            )
            .await
        {
            let data = d.data.map(|p| p.to_vec()).unwrap_or_default();
            t.check(
                "kat-decrypt",
                data == plain,
                json!({"equal": data == plain}),
            );
        }
        t.success("kat-revoke", c, revoke(&kat)).await;
        t.success("kat-destroy", c, destroy(&kat)).await;
    }
    // Another listed principal cannot reach the object (2.1 section 6.1.20).
    t.refused("other-owner-get", other, get(&id)).await;
    if t.success("revoke", c, revoke(&id)).await.is_some() {
        t.check("revoke", true, json!(null));
    }
    if t.success("destroy", c, destroy(&id)).await.is_some() {
        t.check("destroy", true, json!(null));
    }
    t.refused("get-after-destroy", c, get(&id)).await;
    t.refused("get-missing", c, get("cosmian-trial-missing-object"))
        .await;
    t.steps
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: adapter PKI PORT MODE".into());
    }
    let mode = &args[3];
    let pki = Path::new(&args[1]);
    let c = client(pki, &args[2], mode)?;
    // The SDK owns serialization, HTTP, verified TLS and response decoding.
    // Its print_json output is retained verbatim for offline evidence only.
    // Never extract a raw-response UID to continue after a decode failure.
    if mode == "lifecycle" {
        let other = client(pki, &args[2], "other")?;
        let steps = lifecycle(&c, &other).await;
        let failed = steps
            .iter()
            .filter(|s| !matches!(s["status"].as_str(), Some("passed" | "refused")))
            .count();
        println!(
            "{}",
            json!({"event":"sdk_result", "mode":mode, "status": if failed == 0 { "completed" } else { "incomplete" },
                   "steps": steps.len(), "unexpected": failed})
        );
        std::process::exit(if failed == 0 { 0 } else { 2 });
    }
    match exchange(&c, create()).await {
        Ok(response) => {
            let item = match response.batch_item.as_slice() {
                [ResponseMessageBatchItemVersioned::V21(item)] => Some(item),
                _ => None,
            };
            println!(
                "{}",
                json!({"event":"sdk_result", "mode":mode, "status":"decoded",
                "result_status": item.map(|i| format!("{:?}", i.result_status)),
                "result_reason": item.and_then(|i| i.result_reason.map(|r| format!("{r:?}"))),
                "response_debug":format!("{response:?}")})
            );
            std::process::exit(0);
        }
        Err(error) => {
            println!(
                "{}",
                json!({"event":"sdk_result", "mode":mode,
                "status":"error", "error":error.to_string(), "error_debug":format!("{error:?}")})
            );
            std::process::exit(1);
        }
    }
}
