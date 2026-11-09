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

//! Bounded KMIP secret sharing. Protocol authorization and object policy belong
//! to the caller; successful reconstruction does not authenticate a quorum.
//!
//! See docs/objects.md#split-keys for field representations and specification defects.
use anyhow::{Result, bail, ensure};
use crypto_bigint::{
    BoxedUint, Choice,
    ctutils::CtEq,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use openssl::{
    bn::{BigNum, BigNumContext},
    rand::rand_bytes,
};
use std::{
    collections::VecDeque,
    sync::{Mutex, OnceLock},
};
use zeroize::Zeroizing;

pub const MAX_PARTS: usize = 128;
pub const MAX_SECRET_BYTES: usize = 65_536;
pub const MAX_SHARE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BINARY_WORK: usize = 8 * 1024 * 1024;
pub const MAX_PRIME_BITS: usize = 32_768;
pub const MAX_PRIME_WORK: usize = 32 * 1024 * 1024;

/// Resource exhaustion is distinct from invalid sharing parameters.
#[derive(Debug)]
pub struct ResourceLimit(pub &'static str);
impl std::fmt::Display for ResourceLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ResourceLimit {}
fn limit(within: bool, message: &'static str) -> Result<()> {
    if within {
        Ok(())
    } else {
        Err(ResourceLimit(message).into())
    }
}

// Public validated fields only. Reusing one field for a split family must not
// repeat expensive primality tests for every share. Bound entries and total
// key bytes; Montgomery parameters occupy a fixed multiple of that precision.
type PrimeCache = VecDeque<(Vec<u8>, BoxedMontyParams)>;
fn prime_parameters(bytes: &[u8]) -> Result<BoxedMontyParams> {
    static CACHE: OnceLock<Mutex<PrimeCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(VecDeque::new()));
    if let Some((_, params)) = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("prime cache unavailable"))?
        .iter()
        .find(|(key, _)| key == bytes)
    {
        return Ok(params.clone());
    }
    let modulus = BigNum::from_slice(bytes)?;
    let mut context = BigNumContext::new()?;
    ensure!(
        modulus.is_prime_fasttest(64, &mut context, true)?,
        "Prime Field Size is not prime"
    );
    let n = BoxedUint::from_be_slice(bytes, (bytes.len() * 8) as u32)?;
    let params = BoxedMontyParams::new(n.to_odd().unwrap());
    let mut entries = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("prime cache unavailable"))?;
    // Concurrent misses can compute the same public field; retain just one.
    if !entries.iter().any(|(key, _)| key == bytes) {
        while entries.len() >= 16
            || entries.iter().map(|(key, _)| key.len()).sum::<usize>() + bytes.len() > 16_384
        {
            entries.pop_front();
        }
        entries.push_back((bytes.to_vec(), params.clone()));
    }
    Ok(params)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Xor = 1,
    Gf16 = 2,
    Prime = 3,
    Gf8 = 4,
}
impl TryFrom<u32> for Method {
    type Error = anyhow::Error;
    fn try_from(value: u32) -> Result<Self> {
        Ok(match value {
            1 => Self::Xor,
            2 => Self::Gf16,
            3 => Self::Prime,
            4 => Self::Gf8,
            _ => bail!("Unsupported Split Key Method"),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polynomial {
    P283 = 1,
    P285 = 2,
}
impl TryFrom<u32> for Polynomial {
    type Error = anyhow::Error;
    fn try_from(value: u32) -> Result<Self> {
        Ok(match value {
            1 => Self::P283,
            2 => Self::P285,
            _ => bail!("Unsupported Split Key Polynomial"),
        })
    }
}

/// Owned share bytes are cleared on drop. No Debug implementation exposes them.
pub struct Share {
    pub index: u16,
    pub value: Zeroizing<Vec<u8>>,
}

/// A validated sharing configuration. Secret length is public and fixed, even
/// for all-zero or leading-zero secrets. Prime field sizes are unsigned here;
/// the wire adapter must first check signed Big Integer encoding.
pub struct Parameters {
    method: Method,
    parts: usize,
    threshold: usize,
    secret_len: usize,
    width: usize,
    polynomial: Option<Polynomial>,
    prime: Option<BoxedMontyParams>,
    prime_bits: usize,
}
impl Parameters {
    pub fn new(
        method: Method,
        parts: usize,
        threshold: usize,
        secret_len: usize,
        polynomial: Option<Polynomial>,
        prime: Option<&[u8]>,
    ) -> Result<Self> {
        ensure!(parts != 0, "Split Key Parts must be positive");
        limit(parts <= MAX_PARTS, "Split Key Parts exceeds server limit")?;
        ensure!(
            (1..=parts).contains(&threshold),
            "Invalid Split Key Threshold"
        );
        ensure!(secret_len != 0, "Secret length must be positive");
        limit(
            secret_len <= MAX_SECRET_BYTES,
            "Secret length exceeds server limit",
        )?;
        ensure!(
            method != Method::Xor || threshold == parts,
            "XOR requires every share"
        );
        ensure!(
            matches!(method, Method::Gf8 | Method::Gf16) == polynomial.is_some(),
            "Binary fields require an explicit polynomial; other methods forbid it"
        );
        ensure!(
            (method == Method::Prime) == prime.is_some(),
            "Prime Field Size is required only for prime sharing"
        );
        // All resource decisions precede primality testing and share allocation.
        let (width, prime_bits) = if let Some(bytes) = prime {
            ensure!(
                !bytes.is_empty() && bytes[0] != 0,
                "Prime Field Size must be a canonical unsigned integer"
            );
            limit(
                bytes.len() <= MAX_PRIME_BITS / 8,
                "Prime Field Size exceeds server limit",
            )?;
            let bits = bytes.len() * 8 - bytes[0].leading_zeros() as usize;
            ensure!(bits > secret_len * 8, "Prime Field Size must exceed 2^L");
            ensure!(
                bytes[bytes.len() - 1] & 1 == 1,
                "Prime Field Size must be odd"
            );
            (bytes.len(), bits)
        } else {
            (
                if method == Method::Gf16 {
                    secret_len.next_multiple_of(2)
                } else {
                    secret_len
                },
                0,
            )
        };
        limit(
            width * parts <= MAX_SHARE_BYTES,
            "Share allocation exceeds server limit",
        )?;
        let work = parts * threshold * threshold + width * parts * threshold;
        if method == Method::Prime {
            // 64-bit limb units regardless of target architecture. Include the
            // public interpolation table, not just secret evaluation work.
            let limbs = prime_bits.div_ceil(64);
            limit(
                (parts * threshold * threshold + parts * threshold) as u64
                    * limbs as u64
                    * limbs as u64
                    <= MAX_PRIME_WORK as u64,
                "Prime sharing work exceeds server limit",
            )?;
        } else {
            limit(
                work <= MAX_BINARY_WORK,
                "Binary sharing work exceeds server limit",
            )?;
        }
        let prime = if let Some(bytes) = prime {
            // The modulus is public. No secret values enter OpenSSL's variable
            // precision BigNum operations. 64 Miller-Rabin rounds bound the
            // false-prime probability by 2^-128 (plus trial division).
            Some(prime_parameters(bytes)?)
        } else {
            None
        };
        Ok(Self {
            method,
            parts,
            threshold,
            secret_len,
            width,
            polynomial,
            prime,
            prime_bits,
        })
    }
    pub fn share_len(&self) -> usize {
        self.width
    }
    pub fn secret_len(&self) -> usize {
        self.secret_len
    }

    /// Validate one externally registered share without requiring a quorum or
    /// returning reconstructed material. Individual GF shares may contain any
    /// field element, including nonzero bytes in the secret's padding position.
    pub fn validate_share(&self, index: u16, value: &[u8]) -> Result<()> {
        ensure!(
            index > 0 && usize::from(index) <= self.parts,
            "Invalid Key Part Identifier"
        );
        ensure!(
            value.len() == self.width,
            "Share length disagrees with configuration"
        );
        if self.method == Method::Prime {
            self.prime_value(value)?;
        }
        Ok(())
    }

    /// Coefficients are independently uniform, including zero. In particular,
    /// forcing a nonzero highest coefficient would harm perfect secrecy.
    pub fn split(&self, secret: &[u8]) -> Result<Vec<Share>> {
        crate::fips::refuse("Split Key")?;
        self.split_random(secret, &mut |bytes| Ok(rand_bytes(bytes)?))
    }
    fn split_random(
        &self,
        secret: &[u8],
        random: &mut impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<Vec<Share>> {
        ensure!(
            secret.len() == self.secret_len,
            "Secret length disagrees with configuration"
        );
        if self.method == Method::Prime {
            return self.split_prime(secret, random);
        }
        let mut shares: Vec<_> = (1..=self.parts)
            .map(|index| Share {
                index: index as u16,
                value: Zeroizing::new(vec![0; self.width]),
            })
            .collect();
        if self.method == Method::Xor {
            shares[self.parts - 1].value.copy_from_slice(secret);
            for i in 0..self.parts - 1 {
                random(&mut shares[i].value)?;
                for j in 0..self.secret_len {
                    shares[self.parts - 1].value[j] ^= shares[i].value[j];
                }
            }
        } else {
            let field = self.field();
            let mut coefficient = Zeroizing::new(vec![0; self.width]);
            for _ in 1..self.threshold {
                random(&mut coefficient)?;
                for share in &mut shares {
                    field.horner(&mut share.value, share.index, &coefficient);
                }
            }
            coefficient.fill(0);
            coefficient[self.width - self.secret_len..].copy_from_slice(secret);
            for share in &mut shares {
                field.horner(&mut share.value, share.index, &coefficient);
            }
        }
        Ok(shares)
    }

    /// Validate the whole supplied set before returning material. Extra shares
    /// must lie on the same polynomial as the selected threshold shares.
    pub fn join(&self, shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
        crate::fips::refuse("Split Key")?;
        ensure!(
            (self.threshold..=self.parts).contains(&shares.len()),
            "Insufficient or excess shares"
        );
        let mut seen = [false; MAX_PARTS + 1];
        for share in shares {
            let i = usize::from(share.index);
            ensure!(
                i > 0 && i <= self.parts && !seen[i],
                "Invalid or duplicate Key Part Identifier"
            );
            seen[i] = true;
            ensure!(
                share.value.len() == self.width,
                "Share length disagrees with configuration"
            );
        }
        if self.method == Method::Prime {
            return self.join_prime(shares);
        }
        let mut out = Zeroizing::new(vec![0; self.width]);
        if self.method == Method::Xor {
            for share in shares {
                for (dst, src) in out.iter_mut().zip(share.value.iter()) {
                    *dst ^= src;
                }
            }
        } else {
            let field = self.field();
            let basis = &shares[..self.threshold];
            let weights = field.weights(basis, 0);
            field.evaluate(basis, &weights, &mut out);
            let mut difference = 0u8;
            let mut check = Zeroizing::new(vec![0; self.width]);
            for extra in &shares[self.threshold..] {
                field.evaluate(basis, &field.weights(basis, extra.index), &mut check);
                for (a, b) in check.iter().zip(extra.value.iter()) {
                    difference |= a ^ b;
                }
            }
            ensure!(difference == 0, "Shares are inconsistent");
        }
        self.unpad(out)
    }
    fn unpad(&self, mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
        let prefix = bytes.len() - self.secret_len;
        ensure!(
            bytes[..prefix].iter().fold(0, |a, b| a | b) == 0,
            "Reconstructed secret exceeds declared length"
        );
        if prefix != 0 {
            bytes.copy_within(prefix.., 0);
            // Vec::truncate does not wipe the removed portion.
            bytes[self.secret_len..].fill(0);
            bytes.truncate(self.secret_len);
        }
        Ok(bytes)
    }
    fn field(&self) -> BinaryField {
        BinaryField {
            wide: self.method == Method::Gf16,
            polynomial: self.polynomial.unwrap(),
        }
    }
    fn prime_value(&self, bytes: &[u8]) -> Result<Zeroizing<BoxedMontyForm>> {
        let params = self.prime.as_ref().unwrap();
        let integer = Zeroizing::new(BoxedUint::from_be_slice(bytes, params.bits_precision())?);
        ensure!(
            *integer < params.modulus().as_ref(),
            "Share is outside the prime field"
        );
        Ok(Zeroizing::new(BoxedMontyForm::new(
            (*integer).clone(),
            params,
        )))
    }
    fn prime_public(&self, index: u16) -> BoxedMontyForm {
        let value = self
            .prime_value(&index.to_be_bytes())
            .expect("validated field exceeds every index");
        (*value).clone()
    }
    fn sample_prime(
        &self,
        random: &mut impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<Zeroizing<BoxedMontyForm>> {
        let mut bytes = Zeroizing::new(vec![0; self.width]);
        for _ in 0..128 {
            random(&mut bytes)?;
            bytes[0] &= 0xff >> (self.width * 8 - self.prime_bits);
            let n = Zeroizing::new(BoxedUint::from_be_slice(
                &bytes,
                self.prime.as_ref().unwrap().bits_precision(),
            )?);
            if *n < self.prime.as_ref().unwrap().modulus().as_ref() {
                return Ok(Zeroizing::new(BoxedMontyForm::new(
                    (*n).clone(),
                    self.prime.as_ref().unwrap(),
                )));
            }
        }
        bail!("Random provider failed uniform prime-field sampling")
    }
    fn split_prime(
        &self,
        secret: &[u8],
        random: &mut impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<Vec<Share>> {
        let params = self.prime.as_ref().unwrap();
        let points: Vec<_> = (1..=self.parts)
            .map(|i| self.prime_public(i as u16))
            .collect();
        let mut values: Vec<_> = (0..self.parts)
            .map(|_| Zeroizing::new(BoxedMontyForm::zero(params)))
            .collect();
        for _ in 1..self.threshold {
            let coefficient = self.sample_prime(random)?;
            for (value, x) in values.iter_mut().zip(&points) {
                let product = Zeroizing::new(value.mul(x));
                *value = Zeroizing::new(product.add(&coefficient));
            }
        }
        let constant = self.prime_value(secret)?;
        let mut shares = Vec::with_capacity(self.parts);
        for (i, (value, x)) in values.iter().zip(&points).enumerate() {
            let product = Zeroizing::new(value.mul(x));
            let result = Zeroizing::new(product.add(&constant));
            let integer = Zeroizing::new(result.retrieve());
            let bytes = Zeroizing::new(integer.to_be_bytes());
            shares.push(Share {
                index: i as u16 + 1,
                value: Zeroizing::new(bytes[bytes.len() - self.width..].to_vec()),
            });
        }
        Ok(shares)
    }
    // All points and weights are public. Secret ordinates always use the same
    // precision determined by the public modulus, through RustCrypto arithmetic.
    fn prime_weights(&self, basis: &[Share], target: u16) -> Vec<BoxedMontyForm> {
        let params = self.prime.as_ref().unwrap();
        let target = self.prime_public(target);
        basis
            .iter()
            .enumerate()
            .map(|(i, share)| {
                let xi = self.prime_public(share.index);
                let mut numerator = BoxedMontyForm::one(params);
                let mut denominator = BoxedMontyForm::one(params);
                for (j, other) in basis.iter().enumerate() {
                    if i != j {
                        let xj = self.prime_public(other.index);
                        numerator = numerator.mul(&target.sub(&xj));
                        denominator = denominator.mul(&xi.sub(&xj));
                    }
                }
                // Distinct x values in a prime field guarantee an inverse.
                numerator.mul(&denominator.invert().unwrap())
            })
            .collect()
    }
    fn prime_evaluate(
        &self,
        values: &[Zeroizing<BoxedMontyForm>],
        weights: &[BoxedMontyForm],
    ) -> Zeroizing<BoxedMontyForm> {
        let mut sum = Zeroizing::new(BoxedMontyForm::zero(self.prime.as_ref().unwrap()));
        for (value, weight) in values.iter().zip(weights) {
            let product = Zeroizing::new(value.mul(weight));
            sum = Zeroizing::new(sum.add(&product));
        }
        sum
    }
    fn join_prime(&self, shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
        let values = shares
            .iter()
            .map(|s| self.prime_value(&s.value))
            .collect::<Result<Vec<_>>>()?;
        let basis = &shares[..self.threshold];
        let basis_values = &values[..self.threshold];
        let out = self.prime_evaluate(basis_values, &self.prime_weights(basis, 0));
        let mut consistent = Choice::TRUE;
        for (extra, value) in shares[self.threshold..]
            .iter()
            .zip(&values[self.threshold..])
        {
            let predicted =
                self.prime_evaluate(basis_values, &self.prime_weights(basis, extra.index));
            consistent &= predicted.ct_eq(value);
        }
        ensure!(bool::from(consistent), "Shares are inconsistent");
        let integer = Zeroizing::new(out.retrieve());
        let bytes = Zeroizing::new(integer.to_be_bytes());
        self.unpad(Zeroizing::new(bytes[bytes.len() - self.width..].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(method: Method, parts: usize, threshold: usize, len: usize) -> Parameters {
        Parameters::new(
            method,
            parts,
            threshold,
            len,
            matches!(method, Method::Gf8 | Method::Gf16).then_some(Polynomial::P285),
            (method == Method::Prime).then_some([1u8, 1].as_slice()),
        )
        .unwrap()
    }
    fn subset(shares: &[Share], indices: &[usize]) -> Vec<Share> {
        indices
            .iter()
            .map(|i| Share {
                index: shares[*i].index,
                value: Zeroizing::new(shares[*i].value.to_vec()),
            })
            .collect()
    }
    #[test]
    fn all_methods_all_quorums_restore_and_accept_arbitrary_order() {
        for method in [Method::Xor, Method::Gf8, Method::Gf16, Method::Prime] {
            for threshold in 1..=5 {
                if method == Method::Xor && threshold != 5 {
                    continue;
                }
                let p = config(method, 5, threshold, 1);
                for secret in [[0], [1], [128], [255]] {
                    let shares = p.split(&secret).unwrap();
                    for mask in 1u32..32 {
                        let indices: Vec<_> =
                            (0..5).rev().filter(|i| mask & (1 << i) != 0).collect();
                        let selected = subset(&shares, &indices);
                        let result = p.join(&selected);
                        if indices.len() >= threshold {
                            assert_eq!(&*result.unwrap(), &secret);
                        } else {
                            assert!(result.is_err());
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn legacy_gf8_external_shares_identify_polynomial_285() {
        // TC_SJ_3_12_Join_Split_Keys.xml, independently published in OVH's
        // pinned KMIP test corpus. The polynomial choice is material here.
        let values = [
            "66C46A7754F94DE420C7B1A7FFF5EC56",
            "CF93D1E2A7E593CD5B8D6247F4E5D49C",
            "A855B891F61AD9217240D8EC061E37DA",
            "803DBAD55CDD329FAD19D99AE2C5A415",
        ];
        let shares: Vec<_> = values
            .iter()
            .enumerate()
            .map(|(i, value)| Share {
                index: i as u16 + 1,
                value: Zeroizing::new(hex::decode(value).unwrap()),
            })
            .collect();
        let expected: Vec<_> = (1..=16).collect();
        let p = config(Method::Gf8, 4, 2, 16);
        for a in 0..4 {
            for b in a + 1..4 {
                assert_eq!(&*p.join(&subset(&shares, &[a, b])).unwrap(), &expected);
            }
        }
        assert_eq!(&*p.join(&shares).unwrap(), &expected);
        let alternate =
            Parameters::new(Method::Gf8, 4, 2, 16, Some(Polynomial::P283), None).unwrap();
        assert!(alternate.join(&shares).is_err());
    }
    #[test]
    fn field_identities_and_every_nonzero_inverse() {
        for polynomial in [Polynomial::P283, Polynomial::P285] {
            for wide in [false, true] {
                let field = BinaryField { wide, polynomial };
                assert_eq!(field.mul(0, 13), 0);
                assert_eq!(field.mul(1, 1), 1);
                for a in 1..=if wide { 65535 } else { 255 } {
                    assert_eq!(field.mul(a, 1), a);
                    assert_eq!(field.mul(a, field.inverse(a)), 1);
                }
                if wide {
                    assert_eq!(field.mul(0x100, 0x100), 0x013a);
                }
            }
        }
        let fips = BinaryField {
            wide: false,
            polynomial: Polynomial::P283,
        };
        assert_eq!(fips.mul(0x57, 0x13), 0xfe); // FIPS 197 multiplication example.
    }
    #[test]
    fn zero_high_coefficients_are_allowed_and_single_share_needs_no_rng() {
        for method in [Method::Xor, Method::Gf8, Method::Gf16, Method::Prime] {
            let p = config(method, 1, 1, 1);
            let shares = p
                .split_random(&[255], &mut |_| bail!("must not call RNG"))
                .unwrap();
            assert_eq!(&*p.join(&shares).unwrap(), &[255]);
            if method == Method::Xor {
                continue;
            }
            let p = config(method, 5, 3, 1);
            let shares = p
                .split_random(&[42], &mut |b| {
                    b.fill(0);
                    Ok(())
                })
                .unwrap();
            assert_eq!(&*p.join(&shares).unwrap(), &[42]);
            assert!(shares.windows(2).all(|s| s[0].value == s[1].value));
        }
    }
    #[test]
    fn xor_and_prime_deterministic_vectors() {
        let p = config(Method::Xor, 3, 3, 2);
        let mut calls = 0;
        let shares = p
            .split_random(&[0x10, 0x20], &mut |b| {
                calls += 1;
                b.fill(calls);
                Ok(())
            })
            .unwrap();
        assert_eq!(&*shares[0].value, &[1, 1]);
        assert_eq!(&*shares[1].value, &[2, 2]);
        assert_eq!(&*shares[2].value, &[0x13, 0x23]);
        let p = config(Method::Prime, 5, 2, 1);
        let shares = p
            .split_random(&[42], &mut |b| {
                b.copy_from_slice(&[1, 0]);
                Ok(())
            })
            .unwrap();
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(&*share.value, &[0, 41 - i as u8]);
        }
        assert_eq!(&*p.join(&shares).unwrap(), &[42]);
    }
    #[test]
    fn odd_length_and_leading_zero_material_are_preserved() {
        for polynomial in [Polynomial::P283, Polynomial::P285] {
            for len in [1, 2, 3, 31, 32, 33, 255] {
                let p = Parameters::new(Method::Gf16, 5, 3, len, Some(polynomial), None).unwrap();
                let mut secret = vec![0; len];
                secret[len - 1] = 0xff;
                let shares = p.split(&secret).unwrap();
                assert_eq!(shares[0].value.len(), len.next_multiple_of(2));
                assert_eq!(&*p.join(&subset(&shares, &[4, 0, 2])).unwrap(), &secret);
            }
        }
        // NIST P-521's public prime exercises multiple limbs and unused high bits.
        let mut prime = vec![255; 66];
        prime[0] = 1;
        let p = Parameters::new(Method::Prime, 5, 3, 64, None, Some(&prime)).unwrap();
        let mut secret = vec![0; 64];
        secret[63] = 255;
        let shares = p.split(&secret).unwrap();
        assert_eq!(&*p.join(&subset(&shares, &[4, 2, 0])).unwrap(), &secret);
        assert_eq!(&*p.join(&shares).unwrap(), &secret);
    }
    #[test]
    fn corrupt_extras_duplicate_indices_and_invalid_lengths_are_rejected() {
        for method in [Method::Gf8, Method::Gf16, Method::Prime] {
            let p = config(method, 5, 3, 1);
            let mut shares = p.split(&[17]).unwrap();
            let last = shares[4].value.len() - 1;
            shares[4].value[last] ^= 1;
            assert!(p.join(&shares).is_err());
            // An exact quorum has no integrity guarantee: do not pretend that
            // Shamir sharing alone can authenticate corrupt external shares.
            assert_eq!(&*p.join(&subset(&shares, &[0, 1, 2])).unwrap(), &[17]);
            let mut shares = p.split(&[17]).unwrap();
            shares[0].index = 0;
            assert!(p.join(&shares).is_err());
            shares[0].index = 6;
            assert!(p.join(&shares).is_err());
            shares[0].index = 2;
            assert!(p.join(&shares).is_err());
            shares[0].index = 1;
            shares[0].value.push(0);
            assert!(p.join(&shares).is_err());
        }
    }
    #[test]
    fn prime_outside_field_and_reconstruction_overflow_are_rejected() {
        let p = config(Method::Prime, 2, 1, 1);
        let s = |bytes| {
            vec![Share {
                index: 1,
                value: Zeroizing::new(bytes),
            }]
        };
        assert!(p.join(&s(vec![1, 1])).is_err()); // Equal to p, no silent reduction.
        assert!(p.join(&s(vec![1, 0])).is_err()); // 256, exceeds the declared byte.
        let p = config(Method::Gf16, 2, 1, 1);
        assert!(p.join(&s(vec![1, 0])).is_err()); // Nonzero left padding.
    }
    #[test]
    fn rng_failures_propagate_and_rejection_sampling_is_bounded() {
        for method in [Method::Xor, Method::Gf8, Method::Gf16, Method::Prime] {
            let p = config(method, 2, 2, 1);
            assert!(
                p.split_random(&[1], &mut |_| bail!("random failure"))
                    .is_err()
            );
            assert!(p.split(&[1, 2]).is_err());
        }
        let p = config(Method::Prime, 2, 2, 1);
        let mut calls = 0;
        assert!(
            p.split_random(&[1], &mut |b| {
                calls += 1;
                b.fill(255);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(calls, 128);
    }
    #[test]
    fn parameters_and_work_limits_precede_allocations() {
        let p = |method, n, t, len, poly, prime: Option<&[u8]>| {
            Parameters::new(method, n, t, len, poly, prime)
        };
        for (n, t, len) in [
            (0, 0, 1),
            (129, 2, 1),
            (2, 0, 1),
            (2, 3, 1),
            (2, 2, 0),
            (2, 2, 65537),
        ] {
            assert!(p(Method::Gf8, n, t, len, Some(Polynomial::P285), None).is_err());
        }
        assert!(p(Method::Xor, 3, 2, 1, None, None).is_err());
        assert!(p(Method::Gf16, 2, 2, 1, None, None).is_err());
        assert!(
            p(
                Method::Prime,
                2,
                2,
                1,
                Some(Polynomial::P285),
                Some(&[1, 1])
            )
            .is_err()
        );
        for prime in [&[][..], &[0, 1, 1], &[1, 0], &[1, 85], &[2, 49], &[255]] {
            assert!(p(Method::Prime, 2, 2, 1, None, Some(prime)).is_err());
        }
        assert!(p(Method::Gf8, 128, 128, 65536, Some(Polynomial::P285), None).is_err());
        assert!(p(Method::Gf16, 64, 64, 4096, Some(Polynomial::P285), None).is_err());
        assert!(p(Method::Prime, 128, 128, 1, None, Some(&vec![255; 4096])).is_err());
        assert!(p(Method::Prime, 2, 2, 1, None, Some(&vec![255; 4097])).is_err());
        assert!(Method::try_from(5).is_err());
        assert!(Polynomial::try_from(3).is_err());
    }
}

#[derive(Clone, Copy)]
struct BinaryField {
    wide: bool,
    polynomial: Polynomial,
}
impl BinaryField {
    /// Eight fixed iterations, no secret-indexed lookup tables.
    fn mul8(self, mut a: u8, mut b: u8) -> u8 {
        let reduction = match self.polynomial {
            Polynomial::P283 => 0x1b,
            Polynomial::P285 => 0x1d,
        };
        let mut out = 0;
        for _ in 0..8 {
            out ^= a & 0u8.wrapping_sub(b & 1);
            a = (a << 1) ^ (reduction & 0u8.wrapping_sub(a >> 7));
            b >>= 1;
        }
        out
    }
    fn mul(self, a: u16, b: u16) -> u16 {
        if !self.wide {
            return u16::from(self.mul8(a as u8, b as u8));
        }
        let [r, s] = a.to_be_bytes();
        let [u, v] = b.to_be_bytes();
        let ru = self.mul8(r, u);
        let sv = self.mul8(s, v);
        // GF(256)[y]/(y^2+y+0x3a), using the stated quotient rather
        // than the inconsistent printed constant-term formula in KMIP 2.1.
        u16::from_be_bytes([self.mul8(r ^ s, u ^ v) ^ sv, self.mul8(ru, 0x3a) ^ sv])
    }
    fn inverse(self, a: u16) -> u16 {
        let exponent: u32 = if self.wide { 65_534 } else { 254 };
        let mut out = 1;
        for bit in (0..if self.wide { 16 } else { 8 }).rev() {
            out = self.mul(out, out);
            // Exponent and field choice are public.
            if exponent & (1 << bit) != 0 {
                out = self.mul(out, a);
            }
        }
        out
    }
    fn read(self, bytes: &[u8], offset: usize) -> u16 {
        if self.wide {
            u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
        } else {
            u16::from(bytes[offset])
        }
    }
    fn write(self, bytes: &mut [u8], offset: usize, value: u16) {
        if self.wide {
            bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        } else {
            bytes[offset] = value as u8;
        }
    }
    fn horner(self, values: &mut [u8], x: u16, coefficient: &[u8]) {
        for i in (0..values.len()).step_by(if self.wide { 2 } else { 1 }) {
            self.write(
                values,
                i,
                self.mul(self.read(values, i), x) ^ self.read(coefficient, i),
            );
        }
    }
    fn weights(self, basis: &[Share], target: u16) -> Vec<u16> {
        basis
            .iter()
            .enumerate()
            .map(|(i, share)| {
                let mut numerator = 1;
                let mut denominator = 1;
                for (j, other) in basis.iter().enumerate() {
                    if i != j {
                        numerator = self.mul(numerator, target ^ other.index);
                        denominator = self.mul(denominator, share.index ^ other.index);
                    }
                }
                self.mul(numerator, self.inverse(denominator))
            })
            .collect()
    }
    fn evaluate(self, basis: &[Share], weights: &[u16], out: &mut [u8]) {
        for i in (0..out.len()).step_by(if self.wide { 2 } else { 1 }) {
            let mut value = 0;
            for (share, weight) in basis.iter().zip(weights) {
                value ^= self.mul(self.read(&share.value, i), *weight);
            }
            self.write(out, i, value);
        }
    }
}
