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

//! Versioned RSA parameter resolution, separate from provider implementation.
use super::*;

fn unsupported(v: Version) -> Failure {
    fail(
        if v.0 >= 2 { 0x3e } else { 8 },
        "Unsupported RSA parameters",
    )
}
fn digest(algorithm: u32, v: Version) -> R<openssl::hash::MessageDigest> {
    crypto::rsa::digest(algorithm).map_err(|_| unsupported(v))
}
fn mask_hash(cp: &Node, v: Version) -> R<u32> {
    if number(cp, MASK_GENERATOR, 1)? != 1 {
        return Err(unsupported(v));
    }
    let hash = number(cp, MASK_GENERATOR_HASHING_ALGORITHM, 4)?;
    digest(hash, v)?;
    Ok(hash)
}
/// OpenSSL RSA_PSS_SALTLEN_AUTO: maximum salt on Sign, detected on Verify.
const PSS_SALT_AUTO: i32 = -2;
pub(super) fn signature_parameters(
    cp: &Node,
    v: Version,
    bits: u32,
) -> R<crypto::rsa::SignatureParameters> {
    no_fields(
        cp,
        &[
            CRYPTOGRAPHIC_ALGORITHM,
            HASHING_ALGORITHM,
            PADDING_METHOD,
            DIGITAL_SIGNATURE_ALGORITHM,
            MASK_GENERATOR,
            MASK_GENERATOR_HASHING_ALGORITHM,
            SALT_LENGTH,
            TRAILER_FIELD,
        ],
    )?;
    if number(cp, CRYPTOGRAPHIC_ALGORITHM, 4)? != 4 {
        return Err(fail(7, "RSA algorithm mismatch"));
    }
    let combined = cp
        .get(DIGITAL_SIGNATURE_ALGORITHM)
        .map(Node::number)
        .transpose()?;
    let implied_hash = match combined {
        Some(3..=7) => Some(combined.unwrap() + 1),
        Some(8) | None => None,
        Some(_) => return Err(unsupported(v)),
    };
    let hash = match cp.get(HASHING_ALGORITHM) {
        Some(n) => n.number()?,
        None if implied_hash.is_some() => implied_hash.unwrap(),
        None if combined == Some(8) => 4,
        None if v >= Version(3, 0) => 4,
        None => return Err(fail(6, "RSA signature hashing algorithm required")),
    };
    if implied_hash.is_some_and(|h| h != hash) {
        return Err(fail(
            7,
            "Conflicting digital signature and hashing algorithms",
        ));
    }
    let padding = number(cp, PADDING_METHOD, if combined == Some(8) { 10 } else { 8 })?;
    if ![8, 10].contains(&padding) {
        return Err(unsupported(v));
    }
    if combined.is_some_and(|a| (a == 8) != (padding == 10)) {
        return Err(fail(
            7,
            "Conflicting digital signature and padding algorithms",
        ));
    }
    let hash_size = digest(hash, v)?.size();
    let (mgf_hash, salt_len) = if padding == 10 && v == Version(1, 3) {
        // docs/interpretations.md#pss-defaults-in-kmip-13: KMIP 1.3 has
        // no Mask Generator or Salt Length fields and states no PSS defaults.
        // As in the OASIS trace CS-AC-M-2-13 and the PyKMIP server, MGF1 uses
        // the message hash, Sign uses the maximum salt length and Signature
        // Verify accepts any salt length. OpenSSL's RSA_PSS_SALTLEN_AUTO (-2)
        // maximizes the salt when signing and detects it when verifying.
        if number(cp, TRAILER_FIELD, 1)? != 1 {
            return Err(unsupported(v));
        }
        if hash_size + 2 > (bits.saturating_sub(1) as usize).div_ceil(8) {
            return Err(fail(7, "RSA PSS salt does not fit the key and digest"));
        }
        (hash, PSS_SALT_AUTO)
    } else if padding == 10 {
        let mgf_hash = mask_hash(cp, v)?;
        // KMIP 1.4+ explicitly says block size, not digest output length.
        // Earlier editions expose no salt/MGF fields; use PKCS#1 defaults.
        let default_salt = if v >= Version(1, 4) {
            digest(mgf_hash, v)?.block_size()
        } else {
            20
        };
        let salt_len = number(cp, SALT_LENGTH, default_salt as u32)?;
        let encoded_len = (bits.saturating_sub(1) as usize).div_ceil(8);
        if hash_size + 2 > encoded_len
            || salt_len as usize > encoded_len.saturating_sub(hash_size + 2)
        {
            return Err(fail(7, "RSA PSS salt does not fit the key and digest"));
        }
        if number(cp, TRAILER_FIELD, 1)? != 1 {
            return Err(unsupported(v));
        }
        (mgf_hash, salt_len as i32)
    } else {
        if [
            MASK_GENERATOR,
            MASK_GENERATOR_HASHING_ALGORITHM,
            SALT_LENGTH,
            TRAILER_FIELD,
        ]
        .iter()
        .any(|tag| cp.get(*tag).is_some())
        {
            return Err(fail(7, "PSS parameters require PSS padding"));
        }
        (4, 0)
    };
    Ok(crypto::rsa::SignatureParameters {
        hash,
        pss: padding == 10,
        mgf_hash,
        salt_len,
    })
}

pub(super) struct EncryptionParameters<'a> {
    pub parameters: crypto::rsa::OaepParameters<'a>,
    pub modulus_len: usize,
    pub max_input: usize,
}
pub(super) fn encryption_parameters<'a>(
    obj: &Object,
    cp: &'a Node,
    p: &Node,
    v: Version,
    encrypt: bool,
) -> R<EncryptionParameters<'a>> {
    if obj.object_type != if encrypt { 3 } else { 4 } {
        return Err(fail(
            8,
            "RSA encryption requires a public key and decryption a private key",
        ));
    }
    no_fields(
        cp,
        &[
            CRYPTOGRAPHIC_ALGORITHM,
            PADDING_METHOD,
            HASHING_ALGORITHM,
            MASK_GENERATOR,
            MASK_GENERATOR_HASHING_ALGORITHM,
            P_SOURCE,
        ],
    )?;
    if number(cp, CRYPTOGRAPHIC_ALGORITHM, 4)? != 4 {
        return Err(fail(7, "RSA algorithm mismatch"));
    }
    if cp
        .get(PADDING_METHOD)
        .ok_or_else(|| fail(6, "RSA padding method required"))?
        .number()?
        != 2
    {
        return Err(unsupported(v));
    }
    if [
        IV_COUNTER_NONCE,
        AUTHENTICATED_ENCRYPTION_TAG,
        AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,
    ]
    .iter()
    .any(|tag| p.get(*tag).is_some())
    {
        return Err(fail(7, "RSA does not accept IV or AEAD fields"));
    }
    let hash = number(cp, HASHING_ALGORITHM, 4)?;
    let hash_size = digest(hash, v)?.size();
    let mgf_hash = mask_hash(cp, v)?;
    let label = cp
        .get(P_SOURCE)
        .map(Node::byte_string)
        .transpose()?
        .unwrap_or(&[]);
    let parameters = crypto::rsa::OaepParameters {
        hash,
        mgf_hash,
        label,
    };
    fips_policy::rsa_encryption(obj.bits, v)?;
    let modulus_len = (obj.bits as usize).div_ceil(8);
    Ok(EncryptionParameters {
        parameters,
        modulus_len,
        max_input: if encrypt {
            modulus_len.saturating_sub(2 * hash_size + 2)
        } else {
            modulus_len
        },
    })
}

impl Engine {
    pub(super) fn rsa_crypt(
        &self,
        obj: &mut Object,
        cp: &Node,
        p: &Node,
        v: Version,
        encrypt: bool,
    ) -> R<Vec<Node>> {
        let setup = encryption_parameters(obj, cp, p, v, encrypt)?;
        let parameters = setup.parameters;
        let data = p.required(DATA)?.byte_string()?;
        let modulus_len = setup.modulus_len;
        if encrypt && data.len() > setup.max_input {
            return Err(fail(
                7,
                "RSA OAEP plaintext is too long for the key and digest",
            ));
        }
        let out = if encrypt {
            self.consume_protection(obj, data.len(), v, 12)?;
            crypto::rsa::oaep_encrypt(&obj.material, parameters, data)
                .map_err(|_| fail(10, "RSA encryption failed"))?
        } else {
            // Uniform failure: no provider padding details or partial plaintext.
            if data.len() != modulus_len {
                return Err(fail(10, "RSA decryption failed"));
            }
            crypto::rsa::oaep_decrypt(&obj.material, parameters, data)
                .map_err(|_| fail(10, "RSA decryption failed"))?
                .to_vec()
        };
        Ok(vec![
            Node::text(UNIQUE_IDENTIFIER, &obj.id),
            Node::bytes(DATA, out),
        ])
    }
}
