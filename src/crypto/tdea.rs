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

//! Three-key TDEA (NIST SP 800-67 Rev. 2) for legacy KMIP 3DES objects.
//!
//! Only key bundles of three distinct, non-weak DES keys are accepted, so a
//! bundle can never collapse into single DES (K1 = K2 or K2 = K3) or the
//! withdrawn two-key option (K1 = K3). The OpenSSL default provider supplies
//! DES-EDE3; single DES is not reachable through this module.
use super::*;

pub const KEY_BYTES: usize = 24;
pub const BLOCK_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub mode: u32,
    pub padding: u32,
}

/// The DES weak and semi-weak keys (FIPS 74 section 3.6), with odd parity.
/// Comparison ignores the parity bits.
const WEAK: [u64; 16] = [
    0x0101_0101_0101_0101,
    0xFEFE_FEFE_FEFE_FEFE,
    0xE0E0_E0E0_F1F1_F1F1,
    0x1F1F_1F1F_0E0E_0E0E,
    0x011F_011F_010E_010E,
    0x1F01_1F01_0E01_0E01,
    0x01E0_01E0_01F1_01F1,
    0xE001_E001_F101_F101,
    0x01FE_01FE_01FE_01FE,
    0xFE01_FE01_FE01_FE01,
    0x1FE0_1FE0_0EF1_0EF1,
    0xE01F_E01F_F10E_F10E,
    0x1FFE_1FFE_0EFE_0EFE,
    0xFE1F_FE1F_FE0E_FE0E,
    0xE0FE_E0FE_F1FE_F1FE,
    0xFEE0_FEE0_FEF1_FEF1,
];
const PARITY: u64 = 0x0101_0101_0101_0101;

fn component(key: &[u8], index: usize) -> u64 {
    let mut b = [0; 8];
    b.copy_from_slice(&key[index * 8..index * 8 + 8]);
    u64::from_be_bytes(b) & !PARITY
}

/// Rejects anything other than three distinct, non-weak 64-bit DES keys.
/// Parity bits are ignored (SP 800-67 Rev. 2 section 3.3.1: they carry no key
/// information), so keys that differ only in parity count as equal.
pub fn validate_key(key: &[u8]) -> Result<()> {
    if key.len() != KEY_BYTES {
        bail!("three-key TDEA requires 24 bytes of key material");
    }
    let parts = [component(key, 0), component(key, 1), component(key, 2)];
    if parts.iter().any(|p| WEAK.iter().any(|w| w & !PARITY == *p)) {
        bail!("TDEA key bundle contains a weak or semi-weak DES key");
    }
    if parts[0] == parts[1] || parts[1] == parts[2] || parts[0] == parts[2] {
        bail!("TDEA key bundle requires three distinct DES keys");
    }
    Ok(())
}

/// Sets the least significant bit of each byte so every byte has odd parity.
pub fn set_odd_parity(key: &mut [u8]) {
    for b in key {
        *b = (*b & 0xFE) | u8::from((*b >> 1).count_ones() % 2 == 0);
    }
}

/// A fresh odd-parity key bundle from the OpenSSL DRBG.
pub fn generate() -> Result<Zeroizing<Vec<u8>>> {
    // The rejection probability per draw is below 2^-50; the bound only
    // guarantees termination if the generator misbehaves.
    for _ in 0..16 {
        let mut key = random(KEY_BYTES)?;
        set_odd_parity(&mut key);
        if validate_key(&key).is_ok() {
            return Ok(key);
        }
    }
    bail!("TDEA key generation did not yield a valid bundle")
}

pub(crate) fn cipher(mode: u32) -> Result<Cipher> {
    Ok(match mode {
        CBC => Cipher::des_ede3_cbc(),
        ECB => Cipher::des_ede3_ecb(),
        _ => bail!("unsupported TDEA mode"),
    })
}

pub(crate) fn check(key: &[u8], parameters: Parameters, iv: &[u8]) -> Result<()> {
    validate_key(key)?;
    cipher(parameters.mode)?;
    if match parameters.mode {
        ECB => !iv.is_empty(),
        _ => iv.len() != BLOCK_BYTES,
    } {
        bail!("invalid TDEA IV length");
    }
    if ![padding::NONE, padding::PKCS5].contains(&parameters.padding) {
        bail!("unsupported TDEA padding");
    }
    Ok(())
}

/// One-shot TDEA-ECB or TDEA-CBC with optional PKCS#5 padding.
pub fn crypt(
    encrypt: bool,
    key: &[u8],
    parameters: Parameters,
    iv: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    check(key, parameters, iv)?;
    let cipher = cipher(parameters.mode)?;
    let mut c = Crypter::new(
        cipher,
        if encrypt {
            Mode::Encrypt
        } else {
            Mode::Decrypt
        },
        key,
        if parameters.mode == ECB {
            None
        } else {
            Some(iv)
        },
    )?;
    c.pad(parameters.padding == padding::PKCS5);
    let mut out = Zeroizing::new(vec![0; data.len() + BLOCK_BYTES]);
    let used = c.update(data, &mut out)?;
    let end = c.finalize(&mut out[used..])?;
    out.truncate(used + end);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        hex::decode("0123456789abcdef23456789abcdef01456789abcdef0123").unwrap()
    }

    #[test]
    fn sp800_67_example_vector() {
        // NIST SP 800-67 Rev. 2 Appendix B, first block of the TDEA-ECB example.
        let out = crypt(
            true,
            &key(),
            Parameters {
                mode: ECB,
                padding: padding::NONE,
            },
            &[],
            b"The qufc",
        )
        .unwrap();
        assert_eq!(hex::encode(&*out), "a826fd8ce53b855f");
    }

    #[test]
    fn cbc_round_trip_with_padding() {
        let p = Parameters {
            mode: CBC,
            padding: padding::PKCS5,
        };
        let iv = [7; 8];
        let ct = crypt(true, &key(), p, &iv, b"legacy payload").unwrap();
        assert_eq!(ct.len(), 16);
        assert_eq!(
            &*crypt(false, &key(), p, &iv, &ct).unwrap(),
            b"legacy payload"
        );
        assert!(crypt(true, &key(), p, &[0; 16], b"x").is_err());
    }

    #[test]
    fn degenerate_and_weak_bundles_are_rejected() {
        let k = key();
        // K1 = K2 = K3 is single DES.
        assert!(validate_key(&[&k[..8], &k[..8], &k[..8]].concat()).is_err());
        // K1 = K2 and K2 = K3 each collapse to single DES; K1 = K3 is two-key.
        assert!(validate_key(&[&k[..8], &k[..8], &k[16..]].concat()).is_err());
        assert!(validate_key(&[&k[..8], &k[8..16], &k[8..16]].concat()).is_err());
        assert!(validate_key(&[&k[..8], &k[8..16], &k[..8]].concat()).is_err());
        // Equality ignores parity bits.
        let mut parity = k.clone();
        parity[8..16].copy_from_slice(&k[..8]);
        parity[8] ^= 1;
        assert!(validate_key(&parity).is_err());
        // The all-0x01 key used by the KMIP 1.3 CS-BC-M-4-12-3DES-13 trace.
        assert!(validate_key(&[1; 24]).is_err());
        let mut weak = k.clone();
        weak[16..].copy_from_slice(&hex::decode("e0fee0fef1fef1fe").unwrap());
        assert!(validate_key(&weak).is_err());
        assert!(validate_key(&k[..16]).is_err());
        assert!(validate_key(&k).is_ok());
    }

    #[test]
    fn generated_keys_have_odd_parity() {
        let k = generate().unwrap();
        assert_eq!(k.len(), 24);
        assert!(k.iter().all(|b| b.count_ones() % 2 == 1));
        validate_key(&k).unwrap();
    }
}
