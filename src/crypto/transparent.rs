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

//! Validation and conversion of RSA and DSA key components.
//!
//! Imported components are checked mathematically before any DER is produced:
//! RSA private keys through OpenSSL `RSA_check_key` (primality of P and Q,
//! N = PQ and exponent/CRT consistency), DSA domains by primality of P and Q,
//! Q | P-1 and the order of G and Y. Stored forms are PKCS#1 DER for RSA and
//! PKCS#8 / SubjectPublicKeyInfo DER for DSA.
use anyhow::{Result, bail, ensure};
use openssl::{
    bn::{BigNum, BigNumContext, BigNumRef},
    dsa::Dsa,
    pkey::{Id, PKey, Private, Public},
    rsa::Rsa,
};
use std::cmp::Ordering;
use zeroize::Zeroizing;

/// RSA moduli accepted by every import form (PKCS#1, PKCS#8, X.509 and the
/// transparent structures). 1024 bits is the smallest size the OASIS profile
/// test cases register; 8192 bits bounds the cost of public-key operations.
pub const MAX_RSA_BITS: i32 = 8192;
pub const MIN_RSA_BITS: i32 = 1024;
/// Transparent RSA private keys are checked with RSA_check_key (primality of
/// P and Q) and may need factor recovery, whose cost grows with the cube of
/// the size; they are limited to the largest size this server generates.
pub const MAX_RSA_PRIVATE_COMPONENT_BITS: i32 = 4096;
/// Public exponents below 2^256 (NIST SP 800-56B Rev. 2 section 6.2.1 bounds
/// e above by 2^256). Smaller legacy exponents such as 3 stay importable.
const MAX_PUBLIC_EXPONENT_BITS: i32 = 256;
/// FIPS 186-4 section 4.2 lengths L go up to 3072 bits; the profile test cases
/// also register 512-bit domains.
pub const MAX_DSA_BITS: i32 = 3072;
pub const MIN_DSA_BITS: i32 = 512;
/// FIPS 186-4 section 4.2 subgroup sizes N.
const DSA_Q_BITS: [i32; 3] = [160, 224, 256];
const PRIME_CHECKS: i32 = 64;
/// Random bases tried by factor recovery. Each base succeeds with probability
/// at least 1/2 for a valid key (SP 800-56B Rev. 2 Appendix C.2), so a valid
/// key fails with probability below 2^-16; an invalid one costs at most this
/// many modular exponentiations.
const FACTOR_ATTEMPTS: usize = 16;

/// Optional Transparent RSA Private Key fields, in KMIP table order after
/// Modulus: Private Exponent, Public Exponent, P, Q, Prime Exponent P, Prime
/// Exponent Q, CRT Coefficient.
#[derive(Default)]
pub struct RsaPrivate {
    pub n: Option<BigNum>,
    pub d: Option<BigNum>,
    pub e: Option<BigNum>,
    pub p: Option<BigNum>,
    pub q: Option<BigNum>,
    pub dp: Option<BigNum>,
    pub dq: Option<BigNum>,
    pub qinv: Option<BigNum>,
}

fn one() -> Result<BigNum> {
    Ok(BigNum::from_u32(1)?)
}
fn minus_one(a: &BigNumRef) -> Result<BigNum> {
    let mut r = a.to_owned()?;
    r.sub_word(1)?;
    Ok(r)
}
fn rem(a: &BigNumRef, m: &BigNumRef, ctx: &mut BigNumContext) -> Result<BigNum> {
    let mut r = BigNum::new()?;
    r.nnmod(a, m, ctx)?;
    Ok(r)
}
fn is_one(a: &BigNumRef) -> Result<bool> {
    let one = one()?;
    Ok(a.ucmp(&one) == Ordering::Equal && !a.is_negative())
}

fn check_modulus(n: &BigNumRef) -> Result<()> {
    ensure!(
        n.is_odd() && (MIN_RSA_BITS..=MAX_RSA_BITS).contains(&n.num_bits()),
        "RSA modulus must be odd and between {MIN_RSA_BITS} and {MAX_RSA_BITS} bits"
    );
    Ok(())
}
fn check_public_exponent(e: &BigNumRef, n: &BigNumRef) -> Result<()> {
    ensure!(
        e.is_odd()
            && e.num_bits() >= 2
            && e.num_bits() <= MAX_PUBLIC_EXPONENT_BITS
            && e.ucmp(n) == Ordering::Less,
        "RSA public exponent must be odd, at least 3, below 2^256 and below the modulus"
    );
    Ok(())
}
/// 0 < v < n for a private component.
fn check_below(v: &BigNumRef, n: &BigNumRef) -> Result<()> {
    ensure!(
        v.num_bits() > 0 && !v.is_negative() && v.ucmp(n) == Ordering::Less,
        "RSA private component out of range"
    );
    Ok(())
}

/// Shared bounds for RSA keys imported in DER forms (PKCS#1, PKCS#8 and
/// SubjectPublicKeyInfo), so they accept the same sizes and exponents as the
/// transparent structures. Returns the modulus length in bits.
pub fn check_rsa_bounds(n: &BigNumRef, e: &BigNumRef) -> Result<u32> {
    check_modulus(n)?;
    check_public_exponent(e, n)?;
    Ok(n.num_bits() as u32)
}

/// A uniformly random base in [2, n-2].
fn random_base(n: &BigNumRef) -> Result<BigNum> {
    let mut range = n.to_owned()?;
    range.sub_word(3)?;
    let mut g = BigNum::new()?;
    range.rand_range(&mut g)?;
    g.add_word(2)?;
    Ok(g)
}

/// Transparent RSA Public Key: both fields are REQUIRED (KMIP 1.0 table 16,
/// 2.1 table 22, 3.0 table 43). Returns PKCS#1 RSAPublicKey DER.
pub fn rsa_public(n: BigNum, e: BigNum) -> Result<(Vec<u8>, u32)> {
    check_modulus(&n)?;
    check_public_exponent(&e, &n)?;
    let bits = n.num_bits() as u32;
    let key = Rsa::from_public_components(n, e)?;
    Ok((key.public_key_to_der_pkcs1()?, bits))
}

/// Recovers a prime factor from (N, E, D) with the probabilistic method of
/// NIST SP 800-56B Rev. 2 Appendix C.2: random bases g, at most
/// `FACTOR_ATTEMPTS` of them. The first base also checks g^(DE-1) = 1, which
/// fails at once for exponents that cannot belong to N.
fn factor_from_exponents(
    n: &BigNumRef,
    e: &BigNumRef,
    d: &BigNumRef,
    ctx: &mut BigNumContext,
) -> Result<BigNum> {
    let mut k = BigNum::new()?;
    k.checked_mul(d, e, ctx)?;
    k.sub_word(1)?;
    ensure!(
        !k.is_odd() && k.num_bits() > 1,
        "inconsistent RSA exponents"
    );
    let mut t = 0;
    while !k.is_bit_set(t) {
        t += 1;
    }
    let mut r = BigNum::new()?;
    r.rshift(&k, t)?;
    let n1 = minus_one(n)?;
    for attempt in 0..FACTOR_ATTEMPTS {
        let g = random_base(n)?;
        let mut y = BigNum::new()?;
        y.mod_exp(&g, &r, n, ctx)?;
        if attempt == 0 {
            let mut check = y.to_owned()?;
            for _ in 0..t {
                let mut x = BigNum::new()?;
                x.mod_sqr(&check, n, ctx)?;
                check = x;
            }
            ensure!(is_one(&check)?, "inconsistent RSA exponents");
        }
        if is_one(&y)? || y.ucmp(&n1) == Ordering::Equal {
            continue;
        }
        for _ in 0..t {
            let mut x = BigNum::new()?;
            x.mod_sqr(&y, n, ctx)?;
            if is_one(&x)? {
                let y1 = minus_one(&y)?;
                let mut f = BigNum::new()?;
                f.gcd(&y1, n, ctx)?;
                return Ok(f);
            }
            if x.ucmp(&n1) == Ordering::Equal {
                break;
            }
            y = x;
        }
    }
    bail!("could not recover RSA factors from the exponents")
}

/// Recovers the prime p from a CRT exponent dp = d mod (p-1): for a base g,
/// g^(e*dp) = g (mod p), so p divides g^(e*dp) - g. Random bases, at most
/// `FACTOR_ATTEMPTS`.
fn factor_from_crt_exponent(
    n: &BigNumRef,
    e: &BigNumRef,
    dp: &BigNumRef,
    ctx: &mut BigNumContext,
) -> Result<BigNum> {
    let mut exponent = BigNum::new()?;
    exponent.checked_mul(e, dp, ctx)?;
    for _ in 0..FACTOR_ATTEMPTS {
        let g = random_base(n)?;
        let mut a = BigNum::new()?;
        a.mod_exp(&g, &exponent, n, ctx)?;
        let mut diff = BigNum::new()?;
        diff.checked_sub(&a, &g)?;
        let diff = rem(&diff, n, ctx)?;
        let mut f = BigNum::new()?;
        f.gcd(&diff, n, ctx)?;
        if !is_one(&f)? && f.ucmp(n) == Ordering::Less && f.num_bits() > 1 {
            return Ok(f);
        }
    }
    bail!("could not recover RSA factors from the CRT exponent")
}

/// Transparent RSA Private Key. KMIP 1.0-3.0: Modulus is REQUIRED and "One of
/// the following SHALL be present: Private Exponent, P and Q (the first two
/// prime factors of Modulus), or Prime Exponent P and Prime Exponent Q".
/// Missing values are derived; supplied values must agree with the derived
/// key (RSA_check_key). The Public Exponent is needed unless P, Q and the
/// Private Exponent are all present. Returns PKCS#1 RSAPrivateKey DER.
pub fn rsa_private(c: RsaPrivate) -> Result<(Zeroizing<Vec<u8>>, u32)> {
    let Some(n) = c.n else {
        bail!("Modulus is required");
    };
    check_modulus(&n)?;
    ensure!(
        n.num_bits() <= MAX_RSA_PRIVATE_COMPONENT_BITS,
        "transparent RSA private keys are limited to {MAX_RSA_PRIVATE_COMPONENT_BITS} bits"
    );
    ensure!(
        c.d.is_some() || c.p.is_some() && c.q.is_some() || c.dp.is_some() && c.dq.is_some(),
        "Private Exponent, P and Q, or Prime Exponent P and Q is required"
    );
    // Cheap range checks before any exponentiation or primality test.
    for v in [&c.d, &c.p, &c.q, &c.dp, &c.dq, &c.qinv]
        .into_iter()
        .flatten()
    {
        check_below(v, &n)?;
    }
    let mut ctx = BigNumContext::new()?;
    if let Some(e) = &c.e {
        check_public_exponent(e, &n)?;
    }
    let (p, q) = match (c.p, c.q) {
        (Some(p), Some(q)) => (p, q),
        (known_p, known_q) => {
            let e =
                c.e.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Public Exponent is required to factor"))?;
            let (factor, is_p) = if let Some(p) = known_p {
                (p, true)
            } else if let Some(q) = known_q {
                (q, false)
            } else if let Some(dp) = &c.dp {
                (factor_from_crt_exponent(&n, e, dp, &mut ctx)?, true)
            } else if let Some(dq) = &c.dq {
                (factor_from_crt_exponent(&n, e, dq, &mut ctx)?, false)
            } else {
                let d = c.d.as_ref().expect("checked above");
                (factor_from_exponents(&n, e, d, &mut ctx)?, true)
            };
            let mut other = BigNum::new()?;
            let mut remainder = BigNum::new()?;
            other.checked_div(&n, &factor, &mut ctx)?;
            remainder.checked_rem(&n, &factor, &mut ctx)?;
            ensure!(
                remainder.num_bits() == 0 && factor.num_bits() > 1 && other.num_bits() > 1,
                "factor does not divide the modulus"
            );
            if is_p {
                (factor, other)
            } else {
                (other, factor)
            }
        }
    };
    let mut product = BigNum::new()?;
    product.checked_mul(&p, &q, &mut ctx)?;
    ensure!(product.ucmp(&n) == Ordering::Equal, "N is not P*Q");
    let (p1, q1) = (minus_one(&p)?, minus_one(&q)?);
    let mut phi = BigNum::new()?;
    phi.checked_mul(&p1, &q1, &mut ctx)?;
    let mut g = BigNum::new()?;
    g.gcd(&p1, &q1, &mut ctx)?;
    let mut lambda = BigNum::new()?;
    lambda.checked_div(&phi, &g, &mut ctx)?;
    let e = match c.e {
        Some(e) => e,
        None => {
            let mut e = BigNum::new()?;
            e.mod_inverse(c.d.as_ref().expect("checked above"), &lambda, &mut ctx)?;
            check_public_exponent(&e, &n)?;
            e
        }
    };
    let d = match c.d {
        Some(d) => d,
        None => {
            let mut d = BigNum::new()?;
            d.mod_inverse(&e, &lambda, &mut ctx)?;
            d
        }
    };
    let dp = match c.dp {
        Some(v) => v,
        None => rem(&d, &p1, &mut ctx)?,
    };
    let dq = match c.dq {
        Some(v) => v,
        None => rem(&d, &q1, &mut ctx)?,
    };
    let qinv = match c.qinv {
        Some(v) => v,
        None => {
            let mut v = BigNum::new()?;
            v.mod_inverse(&q, &p, &mut ctx)?;
            v
        }
    };
    let bits = n.num_bits() as u32;
    let key = Rsa::from_private_components(n, e, d, p, q, dp, dq, qinv)?;
    ensure!(key.check_key()?, "inconsistent RSA private key");
    Ok((Zeroizing::new(key.private_key_to_der()?), bits))
}

/// FIPS 186-4 domain checks: P and Q prime, Q | P-1, 1 < G < P and G of order Q.
fn check_dsa_domain(
    p: &BigNumRef,
    q: &BigNumRef,
    g: &BigNumRef,
    ctx: &mut BigNumContext,
) -> Result<()> {
    ensure!(
        (MIN_DSA_BITS..=MAX_DSA_BITS).contains(&p.num_bits()) && DSA_Q_BITS.contains(&q.num_bits()),
        "unsupported DSA domain size"
    );
    // Cheapest first: divisibility and the generator's order cost far less
    // than the primality test of P, which runs last.
    ensure!(p.is_odd(), "DSA P must be odd");
    let p1 = minus_one(p)?;
    ensure!(rem(&p1, q, ctx)?.num_bits() == 0, "DSA Q must divide P-1");
    check_subgroup(g, p, q, ctx).map_err(|_| anyhow::anyhow!("invalid DSA generator"))?;
    ensure!(q.is_prime(PRIME_CHECKS, ctx)?, "DSA Q must be prime");
    Ok(())
}
/// The primality test of P, after every cheaper domain and key check.
fn check_dsa_prime(p: &BigNumRef, ctx: &mut BigNumContext) -> Result<()> {
    ensure!(p.is_prime(PRIME_CHECKS, ctx)?, "DSA P must be prime");
    Ok(())
}
/// 1 < v < P-1 and v^Q = 1 (mod P).
fn check_subgroup(
    v: &BigNumRef,
    p: &BigNumRef,
    q: &BigNumRef,
    ctx: &mut BigNumContext,
) -> Result<()> {
    let p1 = minus_one(p)?;
    ensure!(
        v.num_bits() > 1 && !v.is_negative() && v.ucmp(&p1) == Ordering::Less,
        "value out of range"
    );
    let mut r = BigNum::new()?;
    r.mod_exp(v, q, p, ctx)?;
    ensure!(is_one(&r)?, "value is not in the order-Q subgroup");
    Ok(())
}

/// Transparent DSA Public Key (P, Q, G, Y all REQUIRED). Returns
/// SubjectPublicKeyInfo DER.
pub fn dsa_public(p: BigNum, q: BigNum, g: BigNum, y: BigNum) -> Result<(Vec<u8>, u32)> {
    let mut ctx = BigNumContext::new()?;
    check_dsa_domain(&p, &q, &g, &mut ctx)?;
    check_subgroup(&y, &p, &q, &mut ctx)
        .map_err(|_| anyhow::anyhow!("invalid DSA public value"))?;
    check_dsa_prime(&p, &mut ctx)?;
    let bits = p.num_bits() as u32;
    let key = PKey::from_dsa(Dsa::from_public_components(p, q, g, y)?)?;
    Ok((key.public_key_to_der()?, bits))
}

/// Transparent DSA Private Key (P, Q, G, X all REQUIRED); Y = G^X mod P.
/// Returns PKCS#8 DER.
pub fn dsa_private(
    p: BigNum,
    q: BigNum,
    g: BigNum,
    x: BigNum,
) -> Result<(Zeroizing<Vec<u8>>, u32)> {
    let mut ctx = BigNumContext::new()?;
    check_dsa_domain(&p, &q, &g, &mut ctx)?;
    ensure!(
        x.num_bits() > 0 && !x.is_negative() && x.ucmp(&q) == Ordering::Less,
        "DSA X must lie in [1, Q-1]"
    );
    check_dsa_prime(&p, &mut ctx)?;
    let mut y = BigNum::new()?;
    y.mod_exp(&g, &x, &p, &mut ctx)?;
    let bits = p.num_bits() as u32;
    let key = PKey::from_dsa(Dsa::from_private_components(p, q, g, x, y)?)?;
    Ok((Zeroizing::new(key.private_key_to_pkcs8()?), bits))
}

fn copy(n: &BigNumRef) -> Result<BigNum> {
    Ok(n.to_owned()?)
}

/// Validates PKCS#8 / SubjectPublicKeyInfo DSA DER with the same checks as
/// the transparent forms; returns the P length in bits.
pub fn dsa_der(der: &[u8], private: bool) -> Result<u32> {
    if private {
        let key = PKey::private_key_from_der(der)?;
        ensure!(key.id() == Id::DSA, "DSA private key required");
        let k = key.dsa()?;
        dsa_private(
            copy(k.p())?,
            copy(k.q())?,
            copy(k.g())?,
            copy(k.priv_key())?,
        )?;
        let mut ctx = BigNumContext::new()?;
        let mut y = BigNum::new()?;
        y.mod_exp(k.g(), k.priv_key(), k.p(), &mut ctx)?;
        ensure!(
            y.ucmp(k.pub_key()) == Ordering::Equal,
            "DSA Y does not match X"
        );
        Ok(k.p().num_bits() as u32)
    } else {
        let key = PKey::public_key_from_der(der)?;
        ensure!(key.id() == Id::DSA, "DSA public key required");
        let k = key.dsa()?;
        dsa_public(copy(k.p())?, copy(k.q())?, copy(k.g())?, copy(k.pub_key())?)
            .map(|(_, bits)| bits)
    }
}

fn rsa_public_key(der: &[u8]) -> Result<Rsa<Public>> {
    PKey::public_key_from_der(der)
        .and_then(|k| k.rsa())
        .or_else(|_| Rsa::public_key_from_der_pkcs1(der))
        .map_err(Into::into)
}
fn magnitudes(values: &[Option<&BigNumRef>]) -> Vec<Option<Zeroizing<Vec<u8>>>> {
    values
        .iter()
        .map(|v| v.map(|v| Zeroizing::new(v.to_vec())))
        .collect()
}

/// Unsigned big-endian components in KMIP table order. RSA private: Modulus,
/// Private Exponent, Public Exponent, P, Q, Prime Exponent P, Prime Exponent
/// Q, CRT Coefficient. RSA public: Modulus, Public Exponent. DSA: P, Q, G and
/// X (private) or Y (public). Absent optional RSA values are `None`.
pub fn components(der: &[u8], dsa: bool, private: bool) -> Result<Vec<Option<Zeroizing<Vec<u8>>>>> {
    Ok(match (dsa, private) {
        (false, true) => {
            let k: Rsa<Private> = PKey::private_key_from_der(der)?.rsa()?;
            magnitudes(&[
                Some(k.n()),
                Some(k.d()),
                Some(k.e()),
                k.p(),
                k.q(),
                k.dmp1(),
                k.dmq1(),
                k.iqmp(),
            ])
        }
        (false, false) => {
            let k = rsa_public_key(der)?;
            magnitudes(&[Some(k.n()), Some(k.e())])
        }
        (true, true) => {
            let k = PKey::private_key_from_der(der)?.dsa()?;
            magnitudes(&[Some(k.p()), Some(k.q()), Some(k.g()), Some(k.priv_key())])
        }
        (true, false) => {
            let k = PKey::public_key_from_der(der)?.dsa()?;
            magnitudes(&[Some(k.p()), Some(k.q()), Some(k.g()), Some(k.pub_key())])
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_private_recovery_paths_agree() {
        let k = Rsa::generate(1024).unwrap();
        let c = |v: &BigNumRef| Some(v.to_owned().unwrap());
        let check = |parts: RsaPrivate| {
            let (der, bits) = rsa_private(parts).unwrap();
            let got = Rsa::private_key_from_der(&der).unwrap();
            assert!(got.check_key().unwrap());
            assert_eq!(got.n(), k.n());
            assert_eq!(got.e(), k.e());
            assert_eq!(bits, 1024);
        };
        // Private Exponent only (with E): factors recovered per SP 800-56B C.2.
        check(RsaPrivate {
            n: c(k.n()),
            e: c(k.e()),
            d: c(k.d()),
            ..Default::default()
        });
        // P and Q only (with E).
        check(RsaPrivate {
            n: c(k.n()),
            e: c(k.e()),
            p: c(k.p().unwrap()),
            q: c(k.q().unwrap()),
            ..Default::default()
        });
        // Prime Exponent P and Q only (with E).
        check(RsaPrivate {
            n: c(k.n()),
            e: c(k.e()),
            dp: c(k.dmp1().unwrap()),
            dq: c(k.dmq1().unwrap()),
            ..Default::default()
        });
        // P, Q and D without E: E is derived.
        check(RsaPrivate {
            n: c(k.n()),
            d: c(k.d()),
            p: c(k.p().unwrap()),
            q: c(k.q().unwrap()),
            ..Default::default()
        });
    }

    #[test]
    fn rsa_private_rejects_inconsistent_or_insufficient_components() {
        let k = Rsa::generate(1024).unwrap();
        let c = |v: &BigNumRef| Some(v.to_owned().unwrap());
        // Modulus and Public Exponent alone are not a private key.
        assert!(
            rsa_private(RsaPrivate {
                n: c(k.n()),
                e: c(k.e()),
                ..Default::default()
            })
            .is_err()
        );
        // A wrong CRT coefficient fails RSA_check_key.
        let mut bad = BigNum::new().unwrap();
        bad.checked_add(k.iqmp().unwrap(), &one().unwrap()).unwrap();
        assert!(
            rsa_private(RsaPrivate {
                n: c(k.n()),
                e: c(k.e()),
                d: c(k.d()),
                p: c(k.p().unwrap()),
                q: c(k.q().unwrap()),
                dp: c(k.dmp1().unwrap()),
                dq: c(k.dmq1().unwrap()),
                qinv: Some(bad),
            })
            .is_err()
        );
        // P that does not divide N.
        let mut p = k.p().unwrap().to_owned().unwrap();
        p.add_word(2).unwrap();
        assert!(
            rsa_private(RsaPrivate {
                n: c(k.n()),
                e: c(k.e()),
                p: Some(p),
                q: c(k.q().unwrap()),
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn rsa_public_bounds() {
        let k = Rsa::generate(1024).unwrap();
        let c = |v: &BigNumRef| v.to_owned().unwrap();
        assert_eq!(rsa_public(c(k.n()), c(k.e())).unwrap().1, 1024);
        assert!(rsa_public(c(k.n()), BigNum::from_u32(1).unwrap()).is_err());
        assert!(rsa_public(c(k.n()), BigNum::from_u32(65536).unwrap()).is_err());
        let mut even = c(k.n());
        even.add_word(1).unwrap();
        assert!(rsa_public(even, c(k.e())).is_err());
    }

    #[test]
    fn dsa_round_trip_and_rejections() {
        let k = Dsa::generate(2048).unwrap();
        let c = |v: &BigNumRef| v.to_owned().unwrap();
        let (der, bits) = dsa_private(c(k.p()), c(k.q()), c(k.g()), c(k.priv_key())).unwrap();
        assert_eq!(bits, 2048);
        assert_eq!(dsa_der(&der, true).unwrap(), 2048);
        let parts = components(&der, true, true).unwrap();
        assert_eq!(parts[3].as_deref().unwrap(), &k.priv_key().to_vec()[..]);
        let (public, _) = dsa_public(c(k.p()), c(k.q()), c(k.g()), c(k.pub_key())).unwrap();
        assert_eq!(dsa_der(&public, false).unwrap(), 2048);
        // Y outside the subgroup, X out of range, and a composite Q.
        assert!(dsa_public(c(k.p()), c(k.q()), c(k.g()), BigNum::from_u32(2).unwrap()).is_err());
        assert!(dsa_private(c(k.p()), c(k.q()), c(k.g()), c(k.q())).is_err());
        let mut q = c(k.q());
        q.add_word(2).unwrap();
        assert!(dsa_public(c(k.p()), q, c(k.g()), c(k.pub_key())).is_err());
        assert!(
            dsa_public(
                c(k.p()),
                c(k.q()),
                BigNum::from_u32(1).unwrap(),
                c(k.pub_key())
            )
            .is_err()
        );
    }
}
