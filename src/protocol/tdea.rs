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

//! Controlled Triple DES (Cryptographic Algorithm 3DES) compatibility.
//!
//! The Symmetric Key Foundry profiles (Profiles 1.3 through 3.0, "Symmetric
//! Key Foundry Server") require Create with 3DES and Cryptographic Length 168.
//! NIST SP 800-131A Rev. 2 disallows TDEA encryption after 2023 and permits
//! decryption only for legacy use, so the server refuses 3DES unless the
//! operator selects a policy. Only three-key bundles are accepted (see
//! `crypto::tdea`); single DES (algorithm 1) and two-key TDEA are never
//! offered under any policy.
use super::*;
use crate::crypto::tdea as engine;

pub(super) const ALGORITHM: u32 = 2;

/// Server policy for 3DES objects and operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum TripleDesPolicy {
    /// Refuse 3DES Create, Register, Import, Re-key, Encrypt and Decrypt.
    /// Existing 3DES objects stay manageable (Get, attributes, Destroy).
    #[default]
    Disabled,
    /// SP 800-131A Rev. 2 legacy use: Register, Import and Decrypt only.
    LegacyDecrypt,
    /// Full legacy compatibility, including Create, Re-key and Encrypt, as the
    /// Symmetric Key Foundry profiles require.
    Enabled,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Use {
    Generate,
    Import,
    Encrypt,
    Decrypt,
}

impl TripleDesPolicy {
    pub(super) fn permit(self, purpose: Use) -> R<()> {
        let allowed = match self {
            Self::Disabled => false,
            Self::LegacyDecrypt => matches!(purpose, Use::Import | Use::Decrypt),
            Self::Enabled => true,
        };
        if allowed {
            return Ok(());
        }
        Err(fail(
            8,
            match purpose {
                Use::Generate => "3DES key generation is disabled by server policy",
                Use::Import => "3DES key import is disabled by server policy",
                Use::Encrypt => "3DES encryption is disabled by server policy",
                Use::Decrypt => "3DES decryption is disabled by server policy",
            },
        ))
    }
}

/// KMIP 1.0-3.0 Key Block (Cryptographic Length) text: "3DES keys: Typically
/// from 112 to 192 bits (depending upon key length and the presence of parity
/// bits)". 168 is the effective length the Symmetric Key Foundry profiles
/// mandate; 192 counts the parity bits of the same 24-byte bundle. 112 and 128
/// describe two-key TDEA, which is refused.
pub(super) fn validate_length(bits: u32) -> R<()> {
    if ![168, 192].contains(&bits) {
        return Err(fail(
            7,
            "3DES requires a three-key bundle (Cryptographic Length 168 or 192)",
        ));
    }
    Ok(())
}

pub(super) fn generate(policy: TripleDesPolicy, bits: u32) -> R<Vec<u8>> {
    policy.permit(Use::Generate)?;
    validate_length(bits)?;
    Ok(engine::generate()
        .map_err(|_| fail(10, "3DES key generation failed"))?
        .to_vec())
}

/// Checks registered material and returns the Cryptographic Length to record.
/// Declared lengths in the Key Block and the attributes must agree when both
/// are present; an undeclared bundle records the profile length 168.
/// Register of a 3DES key without its Key Value: the import policy and the
/// declared length still apply.
pub(super) fn metadata_only(policy: TripleDesPolicy, bits: u32) -> R<()> {
    policy.permit(Use::Import)?;
    validate_length(bits)
}
pub(super) fn import(
    policy: TripleDesPolicy,
    material: &[u8],
    block: Option<u32>,
    attribute: Option<u32>,
) -> R<u32> {
    policy.permit(Use::Import)?;
    if material.len() != engine::KEY_BYTES {
        return Err(fail(7, "3DES key material must be a 24-byte bundle"));
    }
    if block.zip(attribute).is_some_and(|(a, b)| a != b) {
        return Err(fail(7, "Key length does not match material"));
    }
    let bits = block.or(attribute).unwrap_or(168);
    validate_length(bits)?;
    engine::validate_key(material).map_err(|_| {
        fail(
            7,
            "3DES key bundle must hold three distinct, non-weak DES keys",
        )
    })?;
    Ok(bits)
}

pub(super) fn setup(
    policy: TripleDesPolicy,
    obj: &Object,
    cp: &Node,
    p: &Node,
    encrypt: bool,
) -> R<cipher::Setup> {
    policy.permit(if encrypt { Use::Encrypt } else { Use::Decrypt })?;
    no_fields(
        cp,
        &[
            BLOCK_CIPHER_MODE,
            PADDING_METHOD,
            RANDOM_IV,
            CRYPTOGRAPHIC_ALGORITHM,
            IV_LENGTH,
        ],
    )?;
    if number(cp, CRYPTOGRAPHIC_ALGORITHM, obj.algorithm)? != obj.algorithm {
        return Err(fail(7, "Algorithm mismatch"));
    }
    let mode = cp.required(BLOCK_CIPHER_MODE)?.number()?;
    if ![1, 2].contains(&mode) {
        return Err(fail(8, "3DES supports the CBC and ECB block cipher modes"));
    }
    let pad = number(cp, PADDING_METHOD, 1)?;
    if ![1, 3].contains(&pad) {
        return Err(fail(8, "Unsupported padding for this block cipher mode"));
    }
    if p.get(AUTHENTICATED_ENCRYPTION_TAG).is_some()
        || p.get(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA).is_some()
    {
        return Err(fail(7, "AEAD fields require an authenticated cipher"));
    }
    let generated_iv =
        encrypt && flag(cp, RANDOM_IV, false)? && p.get(IV_COUNTER_NONCE).is_none() && mode != 2;
    let iv = if mode == 2 {
        if p.get(IV_COUNTER_NONCE).is_some() || cp.get(IV_LENGTH).is_some() {
            return Err(fail(7, "ECB does not use an initialization vector"));
        }
        vec![]
    } else if let Some(iv) = p.get(IV_COUNTER_NONCE) {
        iv.byte_string()?.to_vec()
    } else if generated_iv {
        if number(cp, IV_LENGTH, 64)? != 64 {
            return Err(fail(7, "Invalid IV Length"));
        }
        crypto::random(engine::BLOCK_BYTES)?.to_vec()
    } else {
        // A missing IV is Invalid Message in every version
        // (docs/interpretations.md#result-reasons).
        return Err(fail(4, "Initialization vector required"));
    };
    if mode == 1
        && (iv.len() != engine::BLOCK_BYTES
            || number(cp, IV_LENGTH, (iv.len() * 8) as u32)? as usize != iv.len() * 8)
    {
        return Err(fail(
            7,
            "IV Length does not match the cipher or provided vector",
        ));
    }
    engine::validate_key(&obj.material).map_err(|_| fail(10, "Stored 3DES key is unusable"))?;
    Ok(cipher::Setup {
        parameters: crypto::CipherParameters::TripleDes(engine::Parameters { mode, padding: pad }),
        iv,
        generated_iv,
    })
}
