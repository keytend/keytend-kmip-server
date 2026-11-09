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

//! Shared one-shot and multipart symmetric cipher parameter rules.
use super::*;
/// docs/interpretations.md#result-reasons: a required IV or
/// nonce that is absent is reported as Invalid Message in every version, as
/// the OASIS traces CS-BC-M-11/12/13 (1.3-3.0) and other servers do, although
/// 2.0+ also defines Missing Initialization Vector (2.1 Table 478).
fn missing_iv(message: &'static str) -> Failure {
    fail(4, message)
}
/// docs/interpretations.md#result-reasons: an unsupported AEAD Tag Length (2.1 section
/// 4.16 Tag Length) is General Failure in every version, as the traces
/// CS-BC-M-GCM-1 (1.4-3.0) and CS-BC-M-CHACHA20POLY1305-1-30 expect.
pub(super) fn unsupported_tag_length() -> Failure {
    fail(0x100, "Unsupported Tag Length")
}
pub(super) struct Setup {
    pub parameters: crypto::CipherParameters,
    pub iv: Vec<u8>,
    pub generated_iv: bool,
}
pub(super) fn setup(
    obj: &Object,
    cp: &Node,
    p: &Node,
    v: Version,
    encrypt: bool,
    triple_des: TripleDesPolicy,
) -> R<Setup> {
    if obj.object_type == 2 && matches!(obj.algorithm, 28 | 30) {
        fips_policy::cipher_key(obj.algorithm)?;
        return chacha_setup(obj, cp, p, v, encrypt);
    }
    if obj.object_type == 2 && obj.algorithm == tdea::ALGORITHM {
        return tdea::setup(triple_des, obj, cp, p, encrypt);
    }
    if obj.object_type != 2 || obj.algorithm != 3 {
        return Err(fail(8, "AES or RSA key required"));
    }
    no_fields(
        cp,
        &[
            BLOCK_CIPHER_MODE,
            PADDING_METHOD,
            RANDOM_IV,
            CRYPTOGRAPHIC_ALGORITHM,
            TAG_LENGTH,
            IV_LENGTH,
        ],
    )?;
    if number(cp, CRYPTOGRAPHIC_ALGORITHM, 3)? != 3 {
        return Err(fail(7, "Algorithm mismatch"));
    }
    let mode = cp.required(BLOCK_CIPHER_MODE)?.number()?;
    if ![1, 2, 4, 5, 6, 9].contains(&mode) {
        return Err(fail(8, "Unsupported block cipher mode"));
    }
    if mode == 9 && v < Version(1, 4) {
        return Err(fail(8, "AEAD GCM is supported from KMIP 1.4"));
    }
    let pad = number(cp, PADDING_METHOD, 1)?;
    if matches!(mode, 1 | 2) && ![1, 3].contains(&pad) || !matches!(mode, 1 | 2) && pad != 1 {
        return Err(fail(8, "Unsupported padding for this block cipher mode"));
    }
    let tag_len = number(cp, TAG_LENGTH, 16)? as usize;
    if mode == 9 && ![4, 8, 12, 13, 14, 15, 16].contains(&tag_len) {
        return Err(unsupported_tag_length());
    }
    if mode != 9 && cp.get(TAG_LENGTH).is_some() {
        return Err(fail(7, "Tag Length requires an authenticated cipher mode"));
    }
    if mode != 9
        && (p.get(AUTHENTICATED_ENCRYPTION_TAG).is_some()
            || p.get(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA).is_some())
    {
        return Err(fail(7, "AEAD fields require GCM"));
    }
    if encrypt && p.get(AUTHENTICATED_ENCRYPTION_TAG).is_some() {
        return Err(fail(7, "Encrypt cannot accept an authentication tag"));
    }
    let generated_iv =
        encrypt && flag(cp, RANDOM_IV, false)? && p.get(IV_COUNTER_NONCE).is_none() && mode != 2;
    if mode == 9 {
        fips_policy::gcm(
            encrypt,
            tag_len,
            p.get(IV_COUNTER_NONCE).is_some(),
            if generated_iv {
                number(cp, IV_LENGTH, 96)?
            } else {
                u32::MAX
            },
        )?;
    }
    let iv = if mode == 2 {
        if p.get(IV_COUNTER_NONCE).is_some() || cp.get(IV_LENGTH).is_some() {
            return Err(fail(7, "ECB does not use an initialization vector"));
        }
        vec![]
    } else if let Some(iv) = p.get(IV_COUNTER_NONCE) {
        iv.byte_string()?.to_vec()
    } else if generated_iv {
        let bits = number(cp, IV_LENGTH, if mode == 9 { 96 } else { 128 })?;
        if bits == 0 || !bits.is_multiple_of(8) || bits > 8192 {
            return Err(fail(7, "Invalid IV Length"));
        }
        crypto::random((bits / 8) as usize)?.to_vec()
    } else {
        return Err(missing_iv("Initialization vector required"));
    };
    if mode != 2
        && (number(cp, IV_LENGTH, (iv.len() * 8) as u32)? as usize != iv.len() * 8
            || mode != 9 && iv.len() != 16
            || mode == 9 && (iv.is_empty() || iv.len() > 1024))
    {
        return Err(fail(
            7,
            "IV Length does not match the cipher or provided vector",
        ));
    }
    Ok(Setup {
        parameters: crypto::CipherParameters::Aes(crypto::AesParameters {
            mode,
            padding: pad,
            tag_len,
        }),
        iv,
        generated_iv,
    })
}

fn chacha_setup(obj: &Object, cp: &Node, p: &Node, v: Version, encrypt: bool) -> R<Setup> {
    if v < Version(1, 4) {
        return Err(fail(8, "ChaCha20 requires KMIP 1.4"));
    }
    no_fields(
        cp,
        &[
            CRYPTOGRAPHIC_ALGORITHM,
            BLOCK_CIPHER_MODE,
            PADDING_METHOD,
            RANDOM_IV,
            IV_LENGTH,
            TAG_LENGTH,
            COUNTER_LENGTH,
            INITIAL_COUNTER_VALUE,
        ],
    )?;
    if number(cp, CRYPTOGRAPHIC_ALGORITHM, obj.algorithm)? != obj.algorithm {
        return Err(fail(7, "Algorithm mismatch"));
    }
    if number(cp, PADDING_METHOD, 1)? != 1 {
        return Err(fail(7, "ChaCha20 does not use padding"));
    }
    let authenticated = obj.algorithm == 30;
    if authenticated {
        // RFC 8439 section 2.8 defines only a 16-byte tag; truncation is
        // refused (docs/interpretations.md#result-reasons), reported as an
        // unsupported tag length.
        if number(cp, TAG_LENGTH, 16)? != 16 {
            return Err(unsupported_tag_length());
        }
        if number(cp, BLOCK_CIPHER_MODE, 18)? != 18
            || cp.get(COUNTER_LENGTH).is_some()
            || cp.get(INITIAL_COUNTER_VALUE).is_some()
        {
            return Err(fail(7, "Invalid ChaCha20-Poly1305 parameters"));
        }
    } else if cp.get(BLOCK_CIPHER_MODE).is_some()
        || cp.get(TAG_LENGTH).is_some()
        || p.get(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA).is_some()
        || p.get(AUTHENTICATED_ENCRYPTION_TAG).is_some()
    {
        return Err(fail(
            7,
            "Raw ChaCha20 does not use block modes or AEAD fields",
        ));
    }
    if encrypt && p.get(AUTHENTICATED_ENCRYPTION_TAG).is_some() {
        return Err(fail(7, "Encrypt cannot accept authentication tag"));
    }
    if authenticated
        && !encrypt
        && p.get(AUTHENTICATED_ENCRYPTION_TAG)
            .map(Node::byte_string)
            .transpose()?
            .is_some_and(|t| t.len() != 16)
    {
        return Err(fail(7, "ChaCha20-Poly1305 requires a 16-byte tag"));
    }
    let generated_iv = encrypt && flag(cp, RANDOM_IV, false)? && p.get(IV_COUNTER_NONCE).is_none();
    let iv = if let Some(iv) = p.get(IV_COUNTER_NONCE) {
        iv.byte_string()?.to_vec()
    } else if generated_iv {
        let bits = number(cp, IV_LENGTH, 96)?;
        if ![64, 96].contains(&bits) || authenticated && bits != 96 {
            return Err(fail(7, "Invalid ChaCha20 IV Length"));
        }
        crypto::random((bits / 8) as usize)?.to_vec()
    } else {
        return Err(missing_iv("Nonce required"));
    };
    if ![8, 12].contains(&iv.len())
        || authenticated && iv.len() != 12
        || number(cp, IV_LENGTH, (iv.len() * 8) as u32)? != (iv.len() * 8) as u32
    {
        return Err(fail(7, "Invalid ChaCha20 nonce length"));
    }
    let counter = if authenticated {
        0
    } else {
        number(cp, INITIAL_COUNTER_VALUE, 0)? as u64
    };
    if !authenticated
        && number(cp, COUNTER_LENGTH, if iv.len() == 8 { 64 } else { 32 })?
            != if iv.len() == 8 { 64 } else { 32 }
    {
        return Err(fail(7, "Counter Length conflicts with nonce layout"));
    }
    Ok(Setup {
        parameters: crypto::CipherParameters::ChaCha(crypto::chacha::Parameters {
            authenticated,
            initial_counter: counter,
        }),
        iv,
        generated_iv,
    })
}
