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

//! ML-KEM, ML-DSA and SLH-DSA key material for KMIP managed objects
//! (docs/algorithms.md#post-quantum-keys). The provider calls are in the audited
//! `ossl-pqc` crate; this module maps the KMIP Cryptographic Algorithm
//! values and converts between the stored form and the key formats.
//!
//! Stored form: a private key is kept as its PKCS#8 PrivateKeyInfo (OpenSSL
//! writes the "both" form, seed and expanded key, when the key has a seed)
//! and a public key as its X.509 SubjectPublicKeyInfo, whatever Key Format
//! Type the object reports. Every conversion is a parse of that DER.
use anyhow::{Result, anyhow, bail};
use openssl::pkey::{PKey, Private, Public};
pub use ossl_pqc::{Algorithm, Family, SignatureOptions};
use zeroize::Zeroizing;

/// KMIP 3.0 Cryptographic Algorithm values (draft 3.0 Table 552): ML-KEM-512
/// 0x39 through SLH-DSA-SHAKE-256f 0x4A, in the order of `Algorithm::ALL`.
const FIRST: u32 = 0x39;

/// The parameter set of a KMIP Cryptographic Algorithm value.
pub fn parameter_set(kmip: u32) -> Option<Algorithm> {
    let index = kmip.checked_sub(FIRST)? as usize;
    Algorithm::ALL.get(index).copied()
}
/// The KMIP Cryptographic Algorithm value of a parameter set.
pub fn kmip_value(alg: Algorithm) -> u32 {
    FIRST
        + Algorithm::ALL
            .iter()
            .position(|a| *a == alg)
            .expect("listed parameter set") as u32
}

/// ML-KEM ciphertext length in bytes (FIPS 203 Table 3).
pub fn ciphertext_len(alg: Algorithm) -> Option<usize> {
    [
        (Algorithm::ML_KEM_512, 768),
        (Algorithm::ML_KEM_768, 1088),
        (Algorithm::ML_KEM_1024, 1568),
    ]
    .into_iter()
    .find_map(|(a, len)| (a == alg).then_some(len))
}

pub fn generate(alg: Algorithm, seed: Option<&[u8]>) -> Result<PKey<Private>> {
    Ok(match seed {
        Some(seed) => ossl_pqc::from_seed(alg, seed)?,
        None => ossl_pqc::generate(alg)?,
    })
}

/// The stored DER of each half of a pair.
pub fn private_der(key: &PKey<Private>) -> Result<Vec<u8>> {
    Ok(key.private_key_to_pkcs8()?)
}
pub fn public_der(key: &PKey<Private>) -> Result<Vec<u8>> {
    Ok(key.public_key_to_der()?)
}

pub fn load_private(alg: Algorithm, der: &[u8]) -> Result<PKey<Private>> {
    let key = PKey::private_key_from_pkcs8(der)?;
    if !ossl_pqc::is(alg, &key) {
        bail!("private key is not {}", alg.name());
    }
    Ok(key)
}
pub fn load_public(alg: Algorithm, der: &[u8]) -> Result<PKey<Public>> {
    let key = PKey::public_key_from_der(der)?;
    if !ossl_pqc::is(alg, &key) {
        bail!("public key is not {}", alg.name());
    }
    Ok(key)
}

/// Length in bits of a stored key's FIPS byte encoding: KMIP 3.0 section
/// 6.1.11, "The Cryptographic Length attribute on each key SHALL reflect the
/// size of that specific key in bits."
pub fn bits(alg: Algorithm, der: &[u8], private: bool) -> Result<u32> {
    let len = raw(alg, der, private)?.len();
    u32::try_from(len * 8).map_err(|_| anyhow!("key too large"))
}

/// Raw (FIPS encoding) of a stored key.
pub fn raw(alg: Algorithm, der: &[u8], private: bool) -> Result<Zeroizing<Vec<u8>>> {
    Ok(if private {
        let key = load_private(alg, der)?;
        ossl_pqc::raw_private(alg, &key)?
    } else {
        let key = load_public(alg, der)?;
        Zeroizing::new(ossl_pqc::raw_public(alg, &key)?)
    })
}
/// Secret bytes, zeroized on drop.
pub type Secret = Zeroizing<Vec<u8>>;

/// Seed Private Key fields of a stored private key: (seed if held, key).
pub fn seed_and_key(alg: Algorithm, der: &[u8]) -> Result<(Option<Secret>, Secret)> {
    let key = load_private(alg, der)?;
    Ok((ossl_pqc::seed(alg, &key), ossl_pqc::raw_private(alg, &key)?))
}

/// The stored DER for imported material.
pub fn import_raw(alg: Algorithm, bytes: &[u8], private: bool) -> Result<Vec<u8>> {
    Ok(if private {
        ossl_pqc::private_from_raw(alg, bytes)?.private_key_to_pkcs8()?
    } else {
        ossl_pqc::public_from_raw(alg, bytes)?.public_key_to_der()?
    })
}
pub fn import_der(alg: Algorithm, der: &[u8], private: bool) -> Result<Vec<u8>> {
    Ok(if private {
        load_private(alg, der)?.private_key_to_pkcs8()?
    } else {
        load_public(alg, der)?.public_key_to_der()?
    })
}
/// Seed Private Key import (KMIP 3.0 section 3.4): a seed alone is expanded;
/// with both, the seed must derive the given key.
pub fn import_seed(alg: Algorithm, seed: Option<&[u8]>, key: Option<&[u8]>) -> Result<Vec<u8>> {
    let pkey = match (seed, key) {
        (Some(seed), key) => {
            let derived = ossl_pqc::from_seed(alg, seed)?;
            if let Some(key) = key
                && ossl_pqc::raw_private(alg, &derived)?.as_slice() != key
            {
                bail!("seed does not derive the given key");
            }
            derived
        }
        (None, Some(key)) => ossl_pqc::private_from_raw(alg, key)?,
        (None, None) => bail!("Seed Private Key needs a seed or a key"),
    };
    Ok(pkey.private_key_to_pkcs8()?)
}

/// Whether a stored private key and public key form one pair.
pub fn same_pair(alg: Algorithm, private_der: &[u8], public_der: &[u8]) -> Result<bool> {
    let public = load_public(alg, public_der)?;
    Ok(load_private(alg, private_der)?.public_eq(&public))
}

pub fn sign(
    alg: Algorithm,
    der: &[u8],
    message: &[u8],
    options: SignatureOptions<'_>,
) -> Result<Vec<u8>> {
    let key = load_private(alg, der)?;
    Ok(ossl_pqc::sign(alg, &key, message, options)?)
}
pub fn verify(
    alg: Algorithm,
    der: &[u8],
    message: &[u8],
    signature: &[u8],
    options: SignatureOptions<'_>,
) -> Result<bool> {
    let key = load_public(alg, der)?;
    Ok(ossl_pqc::verify(alg, &key, message, signature, options)?)
}
/// (ciphertext, shared secret).
pub fn encapsulate(alg: Algorithm, der: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let key = load_public(alg, der)?;
    Ok(ossl_pqc::encapsulate(alg, &key)?)
}
pub fn decapsulate(alg: Algorithm, der: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let key = load_private(alg, der)?;
    Ok(ossl_pqc::decapsulate(alg, &key, ciphertext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kmip_values_follow_table_552() {
        assert_eq!(parameter_set(0x39), Some(Algorithm::ML_KEM_512));
        assert_eq!(parameter_set(0x3B), Some(Algorithm::ML_KEM_1024));
        assert_eq!(parameter_set(0x3C), Some(Algorithm::ML_DSA_44));
        assert_eq!(parameter_set(0x3E), Some(Algorithm::ML_DSA_87));
        assert_eq!(parameter_set(0x3F), Some(Algorithm::SLH_DSA_SHA2_128S));
        assert_eq!(parameter_set(0x44), Some(Algorithm::SLH_DSA_SHA2_256F));
        assert_eq!(parameter_set(0x45), Some(Algorithm::SLH_DSA_SHAKE_128S));
        assert_eq!(parameter_set(0x4A), Some(Algorithm::SLH_DSA_SHAKE_256F));
        // Hash-SLH-DSA (0x4B-0x56) and Hash-ML-DSA (0x57-0x59) are not
        // implemented by OpenSSL 3.5.
        for v in [0x38, 0x4B, 0x57, 0x5C, 0x5D] {
            assert_eq!(parameter_set(v), None, "{v:#x}");
        }
        for alg in Algorithm::ALL {
            assert_eq!(parameter_set(kmip_value(alg)), Some(alg));
        }
    }

    #[test]
    fn stored_forms_convert_to_every_format() {
        let key = generate(Algorithm::ML_KEM_768, None).unwrap();
        let private = private_der(&key).unwrap();
        let public = public_der(&key).unwrap();
        // FIPS 203 Table 3: dk 2400 bytes, ek 1184 bytes.
        assert_eq!(
            bits(Algorithm::ML_KEM_768, &private, true).unwrap(),
            2400 * 8
        );
        assert_eq!(
            bits(Algorithm::ML_KEM_768, &public, false).unwrap(),
            1184 * 8
        );
        let (seed, dk) = seed_and_key(Algorithm::ML_KEM_768, &private).unwrap();
        assert_eq!(seed.as_ref().unwrap().len(), 64);
        let again = import_seed(
            Algorithm::ML_KEM_768,
            seed.as_deref().map(|s| &s[..]),
            Some(&dk),
        )
        .unwrap();
        assert!(same_pair(Algorithm::ML_KEM_768, &again, &public).unwrap());
        let mut wrong = dk.to_vec();
        wrong[0] ^= 1;
        assert!(
            import_seed(
                Algorithm::ML_KEM_768,
                seed.as_deref().map(|s| &s[..]),
                Some(&wrong)
            )
            .is_err()
        );
        let ek = raw(Algorithm::ML_KEM_768, &public, false).unwrap();
        assert_eq!(
            import_raw(Algorithm::ML_KEM_768, &ek, false).unwrap(),
            public
        );
        assert!(import_der(Algorithm::ML_KEM_512, &public, false).is_err());
        let (ct, ss) = encapsulate(Algorithm::ML_KEM_768, &public).unwrap();
        assert_eq!(ct.len(), ciphertext_len(Algorithm::ML_KEM_768).unwrap());
        assert_eq!(
            decapsulate(Algorithm::ML_KEM_768, &private, &ct).unwrap(),
            ss
        );
    }
}
