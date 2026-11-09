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

//! Cryptographic mechanisms provided by the system OpenSSL provider.
pub mod authentication;
pub mod certificate;
pub mod certificate_attributes;
pub mod chacha;
pub mod derivation;
pub mod dsa;
pub mod ec;
pub mod hashing;
pub mod issuance;
pub mod pgp;
pub mod pgp_certificate;
pub mod pqc;
pub mod rsa;
pub mod split;
pub mod stream;
pub mod tdea;
pub mod transparent;
pub mod wrapping;
use crate::codes::hash::{SHA256, SHA384, SHA512};
use crate::codes::{block_mode::*, padding};
use anyhow::{Result, bail};
use openssl::{
    hash::{MessageDigest, hash},
    pkey::PKey,
    rand::rand_bytes,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};
use zeroize::Zeroizing;
/// Random bytes from the OpenSSL provider's DRBG (in FIPS mode the FIPS
/// provider's), the only randomness source the server uses.
pub fn random(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    if len > 65536 {
        bail!("random request too large");
    }
    let mut b = Zeroizing::new(vec![0; len]);
    rand_bytes(&mut b)?;
    Ok(b)
}
/// A random (version 4) UUID drawn from the provider DRBG rather than the
/// operating system generator the `uuid` crate would use. A failing DRBG
/// means the provider is in its error state; the request then fails closed.
pub fn uuid() -> String {
    let mut bytes = [0; 16];
    rand_bytes(&mut bytes).expect("the OpenSSL DRBG failed");
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string()
}
/// SHA-256 through EVP, so that it runs in the loaded provider. The
/// low-level `openssl::sha` functions bypass providers and are not used.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256_parts(&[data])
}
/// SHA-256 over the concatenation of `parts`.
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = openssl::hash::Hasher::new(MessageDigest::sha256())
        .expect("SHA-256 is unavailable from the OpenSSL provider");
    for part in parts {
        h.update(part).expect("SHA-256 update failed");
    }
    let mut out = [0; 32];
    out.copy_from_slice(&h.finish().expect("SHA-256 failed"));
    out
}
pub fn digest(algorithm: u32) -> Result<MessageDigest> {
    Ok(match algorithm {
        SHA256 => MessageDigest::sha256(),
        SHA384 => MessageDigest::sha384(),
        SHA512 => MessageDigest::sha512(),
        _ => bail!("unsupported hashing algorithm"),
    })
}
pub fn hash_data(algorithm: u32, data: &[u8]) -> Result<Vec<u8>> {
    Ok(hash(digest(algorithm)?, data)?.to_vec())
}
pub fn mac(algorithm: u32, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let k = PKey::hmac(key)?;
    let mut s = Signer::new(digest(algorithm)?, &k)?;
    s.update(data)?;
    Ok(s.sign_to_vec()?)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AesParameters {
    pub mode: u32,
    pub padding: u32,
    /// KMIP Tag Length is in bytes; IV Length is in bits.
    pub tag_len: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherParameters {
    Aes(AesParameters),
    ChaCha(chacha::Parameters),
    TripleDes(tdea::Parameters),
}
pub fn symmetric(
    encrypt: bool,
    key: &[u8],
    parameters: CipherParameters,
    iv: &[u8],
    data: &[u8],
    aad: &[u8],
    tag: Option<&[u8]>,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    match parameters {
        CipherParameters::Aes(p) => aes(encrypt, key, p, iv, data, aad, tag),
        CipherParameters::ChaCha(p) => {
            crate::fips::refuse("ChaCha20")?;
            chacha::crypt(encrypt, key, p, iv, data, aad, tag)
        }
        CipherParameters::TripleDes(p) => {
            crate::fips::refuse("Triple DES")?;
            if !aad.is_empty() || tag.is_some() {
                bail!("TDEA has no authenticated mode");
            }
            Ok((tdea::crypt(encrypt, key, p, iv, data)?, vec![]))
        }
    }
}
/// OpenSSL AES modes. CFB uses full 128-bit feedback segments.
pub fn aes(
    encrypt: bool,
    key: &[u8],
    parameters: AesParameters,
    iv: &[u8],
    data: &[u8],
    aad: &[u8],
    tag: Option<&[u8]>,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let AesParameters {
        mode,
        padding,
        tag_len,
    } = parameters;
    let cipher = match (key.len(), mode) {
        (16, CBC) => Cipher::aes_128_cbc(),
        (24, CBC) => Cipher::aes_192_cbc(),
        (32, CBC) => Cipher::aes_256_cbc(),
        (16, ECB) => Cipher::aes_128_ecb(),
        (24, ECB) => Cipher::aes_192_ecb(),
        (32, ECB) => Cipher::aes_256_ecb(),
        (16, CFB) => Cipher::aes_128_cfb128(),
        (24, CFB) => Cipher::aes_192_cfb128(),
        (32, CFB) => Cipher::aes_256_cfb128(),
        (16, OFB) => Cipher::aes_128_ofb(),
        (24, OFB) => Cipher::aes_192_ofb(),
        (32, OFB) => Cipher::aes_256_ofb(),
        (16, CTR) => Cipher::aes_128_ctr(),
        (24, CTR) => Cipher::aes_192_ctr(),
        (32, CTR) => Cipher::aes_256_ctr(),
        (16, GCM) => Cipher::aes_128_gcm(),
        (24, GCM) => Cipher::aes_192_gcm(),
        (32, GCM) => Cipher::aes_256_gcm(),
        _ => bail!("unsupported AES mechanism"),
    };
    if match mode {
        ECB => !iv.is_empty(),
        GCM => iv.is_empty() || iv.len() > 1024,
        _ => iv.len() != 16,
    } {
        bail!("invalid IV length");
    }
    if matches!(mode, CBC | ECB) && ![padding::NONE, padding::PKCS5].contains(&padding)
        || !matches!(mode, CBC | ECB) && padding != padding::NONE
    {
        bail!("unsupported padding");
    }
    if mode == GCM
        && (![4, 8, 12, 13, 14, 15, 16].contains(&tag_len)
            || !encrypt && tag.map(|t| t.len()) != Some(tag_len))
    {
        bail!("invalid GCM parameters");
    }
    if mode != GCM && (!aad.is_empty() || tag.is_some()) {
        bail!("authentication fields require GCM");
    }
    if encrypt && tag.is_some() {
        bail!("encryption cannot accept an authentication tag");
    }
    let mut c = Crypter::new(
        cipher,
        if encrypt {
            Mode::Encrypt
        } else {
            Mode::Decrypt
        },
        key,
        if mode == ECB { None } else { Some(iv) },
    )?;
    c.pad(matches!(mode, CBC | ECB) && padding == padding::PKCS5);
    if mode == GCM {
        c.aad_update(aad)?;
        if !encrypt {
            c.set_tag(tag.unwrap())?;
        }
    }
    let mut out = Zeroizing::new(vec![0; data.len() + cipher.block_size()]);
    let used = c.update(data, &mut out)?;
    let end = c.finalize(&mut out[used..])?;
    out.truncate(used + end);
    let mut auth = vec![];
    if mode == GCM && encrypt {
        auth.resize(tag_len, 0);
        c.get_tag(&mut auth)?;
    }
    Ok((out, auth))
}
