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

//! Explicit HMAC and AES-CMAC mechanisms, independent of a key's storage label.
use anyhow::{Result, bail};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer, symm::Cipher};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    Hmac(u32),
    Cmac,
}
pub fn hmac_hash(algorithm: u32) -> Option<u32> {
    match algorithm {
        7..=11 => Some(algorithm - 3),
        12 => Some(3),
        35..=38 => Some(algorithm - 21),
        _ => None,
    }
}
pub fn digest(hash: u32) -> Result<MessageDigest> {
    Ok(match hash {
        3 => MessageDigest::md5(),
        4 => MessageDigest::sha1(),
        5 => MessageDigest::sha224(),
        6 => MessageDigest::sha256(),
        7 => MessageDigest::sha384(),
        8 => MessageDigest::sha512(),
        14 => MessageDigest::sha3_224(),
        15 => MessageDigest::sha3_256(),
        16 => MessageDigest::sha3_384(),
        17 => MessageDigest::sha3_512(),
        _ => bail!("Unsupported HMAC digest"),
    })
}
pub fn compute(mechanism: Mechanism, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let pkey = match mechanism {
        Mechanism::Hmac(_) => PKey::hmac(key)?,
        Mechanism::Cmac => {
            let cipher = match key.len() {
                16 => Cipher::aes_128_cbc(),
                24 => Cipher::aes_192_cbc(),
                32 => Cipher::aes_256_cbc(),
                _ => bail!("Invalid AES-CMAC key length"),
            };
            PKey::cmac(&cipher, key)?
        }
    };
    let mut signer = match mechanism {
        Mechanism::Hmac(hash) => Signer::new(digest(hash)?, &pkey)?,
        Mechanism::Cmac => Signer::new_without_digest(&pkey)?,
    };
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}
