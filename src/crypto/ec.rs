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

//! Named Weierstrass curves, canonical DER storage and strict EC validation.
use anyhow::{Result, bail};
use openssl::{
    asn1::Asn1Object,
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::hash,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    pkey_ctx::PkeyCtx,
};
use zeroize::Zeroizing;

// KMIP's first 68 Recommended Curve values, in wire enumeration order, with
// their namedCurve object identifiers (SEC 2, ANSI X9.62, RFC 5639).
const CURVES: &[(&str, &str)] = &[
    ("prime192v1", "1.2.840.10045.3.1.1"),
    ("sect163k1", "1.3.132.0.1"),
    ("sect163r2", "1.3.132.0.15"),
    ("secp224r1", "1.3.132.0.33"),
    ("sect233k1", "1.3.132.0.26"),
    ("sect233r1", "1.3.132.0.27"),
    ("prime256v1", "1.2.840.10045.3.1.7"),
    ("sect283k1", "1.3.132.0.16"),
    ("sect283r1", "1.3.132.0.17"),
    ("secp384r1", "1.3.132.0.34"),
    ("sect409k1", "1.3.132.0.36"),
    ("sect409r1", "1.3.132.0.37"),
    ("secp521r1", "1.3.132.0.35"),
    ("sect571k1", "1.3.132.0.38"),
    ("sect571r1", "1.3.132.0.39"),
    ("secp112r1", "1.3.132.0.6"),
    ("secp112r2", "1.3.132.0.7"),
    ("secp128r1", "1.3.132.0.28"),
    ("secp128r2", "1.3.132.0.29"),
    ("secp160k1", "1.3.132.0.9"),
    ("secp160r1", "1.3.132.0.8"),
    ("secp160r2", "1.3.132.0.30"),
    ("secp192k1", "1.3.132.0.31"),
    ("secp224k1", "1.3.132.0.32"),
    ("secp256k1", "1.3.132.0.10"),
    ("sect113r1", "1.3.132.0.4"),
    ("sect113r2", "1.3.132.0.5"),
    ("sect131r1", "1.3.132.0.22"),
    ("sect131r2", "1.3.132.0.23"),
    ("sect163r1", "1.3.132.0.2"),
    ("sect193r1", "1.3.132.0.24"),
    ("sect193r2", "1.3.132.0.25"),
    ("sect239k1", "1.3.132.0.3"),
    ("prime192v2", "1.2.840.10045.3.1.2"),
    ("prime192v3", "1.2.840.10045.3.1.3"),
    ("prime239v1", "1.2.840.10045.3.1.4"),
    ("prime239v2", "1.2.840.10045.3.1.5"),
    ("prime239v3", "1.2.840.10045.3.1.6"),
    ("c2pnb163v1", "1.2.840.10045.3.0.1"),
    ("c2pnb163v2", "1.2.840.10045.3.0.2"),
    ("c2pnb163v3", "1.2.840.10045.3.0.3"),
    ("c2pnb176v1", "1.2.840.10045.3.0.4"),
    ("c2tnb191v1", "1.2.840.10045.3.0.5"),
    ("c2tnb191v2", "1.2.840.10045.3.0.6"),
    ("c2tnb191v3", "1.2.840.10045.3.0.7"),
    ("c2pnb208w1", "1.2.840.10045.3.0.10"),
    ("c2tnb239v1", "1.2.840.10045.3.0.11"),
    ("c2tnb239v2", "1.2.840.10045.3.0.12"),
    ("c2tnb239v3", "1.2.840.10045.3.0.13"),
    ("c2pnb272w1", "1.2.840.10045.3.0.16"),
    ("c2pnb304w1", "1.2.840.10045.3.0.17"),
    ("c2tnb359v1", "1.2.840.10045.3.0.18"),
    ("c2pnb368w1", "1.2.840.10045.3.0.19"),
    ("c2tnb431r1", "1.2.840.10045.3.0.20"),
    ("brainpoolP160r1", "1.3.36.3.3.2.8.1.1.1"),
    ("brainpoolP160t1", "1.3.36.3.3.2.8.1.1.2"),
    ("brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3"),
    ("brainpoolP192t1", "1.3.36.3.3.2.8.1.1.4"),
    ("brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5"),
    ("brainpoolP224t1", "1.3.36.3.3.2.8.1.1.6"),
    ("brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7"),
    ("brainpoolP256t1", "1.3.36.3.3.2.8.1.1.8"),
    ("brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9"),
    ("brainpoolP320t1", "1.3.36.3.3.2.8.1.1.10"),
    ("brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11"),
    ("brainpoolP384t1", "1.3.36.3.3.2.8.1.1.12"),
    ("brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13"),
    ("brainpoolP512t1", "1.3.36.3.3.2.8.1.1.14"),
];
/// The 13 curves the server implements: P-224 (4), P-256 (7), P-384 (10),
/// P-521 (13), secp256k1 (25) and brainpoolP256r1 through brainpoolP512t1
/// (61-68). As docs/interpretations.md#supported-elliptic-curves says, the
/// other KMIP curves are removed, for parity with RHEL 9's OpenSSL in the UBI
/// image, which offers only these. The TLS listeners accept certificates on
/// any of them (`--ec-curves` does not change TLS). KMIP operations use
/// `supported`, which `--ec-curves` narrows.
pub fn implemented(curve: u32) -> bool {
    nist(curve) || matches!(curve, 25 | 61..=68)
}
/// The NIST prime curves P-224, P-256, P-384 and P-521 (FIPS 186-5,
/// SP 800-186), the `--ec-curves nist` set.
pub fn nist(curve: u32) -> bool {
    matches!(curve, 4 | 7 | 10 | 13)
}
/// The curves KMIP operations may use (`--ec-curves`, `KMIP_EC_CURVES`;
/// docs/interpretations.md#supported-elliptic-curves).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum EcCurves {
    /// P-224, P-256, P-384 and P-521 only (default).
    #[default]
    Nist,
    /// Also secp256k1 and brainpoolP256/320/384/512 r1 and t1.
    Extended,
}
thread_local! {
    /// The curve set of the request being processed on this thread.
    static ACTIVE: std::cell::Cell<EcCurves> = const { std::cell::Cell::new(EcCurves::Nist) };
}
/// The curve set that applies on this thread. The engine sets it around each
/// request (`enter`); it is `nist` everywhere else.
pub fn active() -> EcCurves {
    ACTIVE.with(std::cell::Cell::get)
}
/// Use `curves` on this thread until the guard drops.
pub fn enter(curves: EcCurves) -> Guard {
    Guard(ACTIVE.with(|a| a.replace(curves)), std::marker::PhantomData)
}
/// Run `f` with `curves` on this thread, restoring the previous set
/// afterwards (also on unwind).
pub fn scope<T>(curves: EcCurves, f: impl FnOnce() -> T) -> T {
    let _guard = enter(curves);
    f()
}
/// Restores the previous curve set; not `Send`, so it drops on its own thread.
pub struct Guard(EcCurves, std::marker::PhantomData<*const ()>);
impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with(|a| a.set(self.0));
    }
}
/// Whether KMIP operations on this thread may use `curve`: the NIST curves,
/// and with `--ec-curves extended` the other implemented curves. KMIP leaves
/// the supported curves to the server: the Cryptographic Domain Parameters
/// are OPTIONAL fields (1.0-1.4 section 3.7, 2.0/2.1 section 4.14), and an
/// unsupported optional feature is Feature Not Supported (1.0-1.4 section
/// 6.10). FIPS mode further limits them to the NIST curves (src/fips.rs) in
/// either setting.
pub fn supported(curve: u32) -> bool {
    nist(curve) || active() == EcCurves::Extended && implemented(curve)
}
/// A KMIP Recommended Curve the server does not support, or an EC key on a
/// named curve KMIP does not list. Decided from the server's own table, before
/// OpenSSL is asked, so every OpenSSL build answers alike.
#[derive(Debug, thiserror::Error)]
#[error("unsupported EC curve")]
pub struct UnsupportedCurve;

pub fn group(curve: u32) -> Result<EcGroup> {
    let (name, _) = CURVES
        .get(curve.wrapping_sub(1) as usize)
        .filter(|_| supported(curve))
        .ok_or(UnsupportedCurve)?;
    Ok(EcGroup::from_curve_name(Asn1Object::from_str(name)?.nid())?)
}
fn curve_id(nid: Nid) -> Result<u32> {
    for (i, (name, _)) in CURVES.iter().enumerate() {
        let id = i as u32 + 1;
        if supported(id) && Asn1Object::from_str(name)?.nid() == nid {
            return Ok(id);
        }
    }
    Err(UnsupportedCurve.into())
}

/// DER reader for the few structures whose namedCurve is needed.
struct Der<'a>(&'a [u8]);
impl<'a> Der<'a> {
    /// The next element: (tag, contents).
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.0.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let len = rest[..n].iter().fold(0usize, |a, b| a << 8 | *b as usize);
            (len, &rest[n..])
        };
        if rest.len() < len {
            return None;
        }
        self.0 = &rest[len..];
        Some((tag, &rest[..len]))
    }
    fn sequence(data: &'a [u8]) -> Option<Self> {
        match Der(data).next()? {
            (0x30, inner) => Some(Der(inner)),
            _ => None,
        }
    }
}
/// Dotted text of an OBJECT IDENTIFIER's contents.
fn oid_text(contents: &[u8]) -> Option<String> {
    let mut arcs = vec![];
    let mut value: u64 = 0;
    for b in contents {
        value = value.checked_mul(128)? | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    let first = *arcs.first()?;
    let top = (first / 40).min(2);
    let mut text = format!("{}.{}", top, first - 40 * top);
    for arc in &arcs[1..] {
        text.push_str(&format!(".{arc}"));
    }
    Some(text)
}
/// The KMIP curve number of a namedCurve OID; 0 when KMIP does not list it.
fn curve_of_oid(contents: &[u8]) -> u32 {
    let text = oid_text(contents).unwrap_or_default();
    CURVES
        .iter()
        .position(|(_, oid)| *oid == text)
        .map_or(0, |i| i as u32 + 1)
}
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// The namedCurve of an id-ecPublicKey AlgorithmIdentifier.
fn algorithm_curve(algorithm: &[u8]) -> Option<u32> {
    let mut a = Der(algorithm);
    match (a.next()?, a.next()?) {
        ((0x06, EC_PUBLIC_KEY), (0x06, curve)) => Some(curve_of_oid(curve)),
        _ => None,
    }
}
/// The KMIP Recommended Curve of a DER EC key (SubjectPublicKeyInfo, PKCS#8
/// or SEC 1 ECPrivateKey) with a named curve: `Some(0)` for a curve KMIP does
/// not list, `None` for anything else (not EC, explicit parameters or
/// malformed), which is left to OpenSSL.
pub fn key_curve(der: &[u8]) -> Option<u32> {
    let mut top = Der::sequence(der)?;
    match top.next()? {
        // SubjectPublicKeyInfo
        (0x30, algorithm) => algorithm_curve(algorithm),
        (0x02, _) => match top.next()? {
            // PKCS#8 PrivateKeyInfo
            (0x30, algorithm) => algorithm_curve(algorithm),
            // SEC 1 ECPrivateKey: parameters [0] namedCurve
            (0x04, _) => loop {
                match top.next()? {
                    (0xa0, parameters) => match Der(parameters).next()? {
                        (0x06, curve) => break Some(curve_of_oid(curve)),
                        _ => break None,
                    },
                    _ => continue,
                }
            },
            _ => None,
        },
        _ => None,
    }
}
/// The KMIP Recommended Curve of a PKCS#10 request's EC subject key, as
/// `key_curve` reads it.
pub fn request_curve(der: &[u8]) -> Option<u32> {
    let mut info = Der::sequence(Der::sequence(der)?.0)?;
    // version, subject, subjectPKInfo
    info.next()?;
    info.next()?;
    match info.next()? {
        (0x30, spki) => match Der(spki).next()? {
            (0x30, algorithm) => algorithm_curve(algorithm),
            _ => None,
        },
        _ => None,
    }
}
/// The KMIP Recommended Curve of an X.509 certificate's EC subject key, as
/// `key_curve` reads it.
pub fn certificate_curve(der: &[u8]) -> Option<u32> {
    let mut tbs = Der::sequence(Der::sequence(der)?.0)?;
    let mut field = tbs.next()?;
    if field.0 == 0xa0 {
        field = tbs.next()?;
    }
    // serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    for _ in 0..5 {
        field = tbs.next()?;
    }
    match field {
        (0x30, spki) => match Der(spki).next()? {
            (0x30, algorithm) => algorithm_curve(algorithm),
            _ => None,
        },
        _ => None,
    }
}
/// The stored transparent components of a key, read from its DER without
/// OpenSSL and without curve arithmetic: (curve, D) of a PKCS#8 EC private
/// key, as the minimal big-endian scalar, or (curve, Q) of a
/// SubjectPublicKeyInfo, as the uncompressed point. Used to return a key in
/// its stored form when KMIP operations cannot use its curve (`supported`:
/// an extended curve under `--ec-curves nist`, or a removed curve); `None`
/// for anything else, which the caller refuses as before.
pub fn stored_components(der: &[u8], is_private: bool) -> Option<(u32, Vec<u8>)> {
    let mut top = Der::sequence(der)?;
    if is_private {
        // PrivateKeyInfo: version 0, AlgorithmIdentifier, OCTET STRING.
        match top.next()? {
            (0x02, [0]) => (),
            _ => return None,
        }
        let curve = match top.next()? {
            (0x30, algorithm) => algorithm_curve(algorithm)?,
            _ => return None,
        };
        let (0x04, inner) = top.next()? else {
            return None;
        };
        // ECPrivateKey: version 1, privateKey OCTET STRING, ...
        let mut ec = Der::sequence(inner)?;
        match ec.next()? {
            (0x02, [1]) => (),
            _ => return None,
        }
        let (0x04, d) = ec.next()? else {
            return None;
        };
        let start = d.iter().position(|b| *b != 0)?;
        Some((curve, d[start..].to_vec()))
    } else {
        let curve = match top.next()? {
            (0x30, algorithm) => algorithm_curve(algorithm)?,
            _ => return None,
        };
        match top.next()? {
            (0x03, [0, point @ ..]) if point.first() == Some(&4) && point.len() % 2 == 1 => {
                Some((curve, point.to_vec()))
            }
            _ => None,
        }
    }
}
/// Key generation through EVP, so that it runs in the loaded provider (the
/// low-level EC_KEY_generate_key would bypass it).
pub fn generate(curve: u32) -> Result<PKey<Private>> {
    let group = group(curve)?;
    let nid = group
        .curve_name()
        .ok_or_else(|| anyhow::anyhow!("unnamed EC group"))?;
    let mut ctx = PkeyCtx::new_id(Id::EC)?;
    ctx.keygen_init()?;
    ctx.set_ec_paramgen_curve_nid(nid)?;
    Ok(ctx.keygen()?)
}
fn private(data: &[u8]) -> Result<PKey<Private>> {
    let key = PKey::private_key_from_der(data)?;
    validate_private(&key)?;
    Ok(key)
}
fn public(data: &[u8]) -> Result<PKey<Public>> {
    let key = PKey::public_key_from_der(data)?;
    validate_public(&key)?;
    Ok(key)
}
fn validate_private(key: &PKey<Private>) -> Result<()> {
    let k = key.ec_key()?;
    k.check_key()?;
    if k.group().curve_name().is_none() {
        bail!("explicit EC groups are unsupported");
    }
    curve_id(k.group().curve_name().unwrap())?;
    Ok(())
}
fn validate_public(key: &PKey<Public>) -> Result<()> {
    let k = key.ec_key()?;
    k.check_key()?;
    if k.group().curve_name().is_none() || k.public_key().is_infinity(k.group()) {
        bail!("invalid EC public key");
    }
    curve_id(k.group().curve_name().unwrap())?;
    Ok(())
}
pub fn info(data: &[u8], is_private: bool) -> Result<(u32, u32)> {
    let (nid, bits) = if is_private {
        let k = private(data)?;
        let ec = k.ec_key()?;
        (ec.group().curve_name().unwrap(), ec.group().degree())
    } else {
        let k = public(data)?;
        let ec = k.ec_key()?;
        (ec.group().curve_name().unwrap(), ec.group().degree())
    };
    Ok((curve_id(nid)?, bits))
}
pub fn import_der(data: &[u8], is_private: bool, format: u32) -> Result<Zeroizing<Vec<u8>>> {
    if is_private {
        let key = match format {
            4 => PKey::private_key_from_pkcs8(data)?,
            6 => PKey::from_ec_key(EcKey::private_key_from_der(data)?)?,
            _ => bail!("unsupported EC private format"),
        };
        validate_private(&key)?;
        Ok(Zeroizing::new(key.private_key_to_pkcs8()?))
    } else {
        if format != 5 {
            bail!("unsupported EC public format");
        }
        let key = public(data)?;
        Ok(Zeroizing::new(key.public_key_to_der()?))
    }
}
pub fn export_der(data: &[u8], is_private: bool, format: u32) -> Result<Zeroizing<Vec<u8>>> {
    if is_private {
        let key = private(data)?;
        Ok(Zeroizing::new(match format {
            4 => key.private_key_to_pkcs8()?,
            6 => key.ec_key()?.private_key_to_der()?,
            _ => bail!("unsupported EC private format"),
        }))
    } else {
        if format != 5 {
            bail!("unsupported EC public format");
        }
        Ok(Zeroizing::new(public(data)?.public_key_to_der()?))
    }
}
struct Scalar(BigNum);
impl Drop for Scalar {
    fn drop(&mut self) {
        self.0.clear();
    }
}
pub fn import_scalar(curve: u32, value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let group = group(curve)?;
    let mut d = Scalar(BigNum::from_slice(value)?);
    d.0.set_const_time();
    let mut ctx = BigNumContext::new_secure()?;
    let mut order = BigNum::new()?;
    group.order(&mut order, &mut ctx)?;
    if d.0.num_bits() == 0 || d.0 >= order {
        bail!("EC scalar out of range");
    }
    let mut point = EcPoint::new(&group)?;
    point.mul_generator2(&group, &d.0, &mut ctx)?;
    let key = PKey::from_ec_key(EcKey::from_private_components(&group, &d.0, &point)?)?;
    validate_private(&key)?;
    Ok(Zeroizing::new(key.private_key_to_pkcs8()?))
}
pub fn import_point(curve: u32, value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let group = group(curve)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, value, &mut ctx)?;
    let key = PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)?;
    validate_public(&key)?;
    Ok(Zeroizing::new(key.public_key_to_der()?))
}
pub fn scalar(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(
        private(data)?.ec_key()?.private_key().to_vec(),
    ))
}
pub fn point(data: &[u8], compression: u32) -> Result<Vec<u8>> {
    let key = public(data)?;
    let ec = key.ec_key()?;
    curve_id(ec.group().curve_name().unwrap())?;
    // Every supported curve is over a prime field, so compressed char-2 (3)
    // never matches.
    let form = match compression {
        1 => PointConversionForm::UNCOMPRESSED,
        2 => PointConversionForm::COMPRESSED,
        4 => PointConversionForm::HYBRID,
        _ => bail!("compression does not match curve field"),
    };
    let mut ctx = BigNumContext::new()?;
    Ok(ec.public_key().to_bytes(ec.group(), form, &mut ctx)?)
}
fn input(hash_id: u32, data: &[u8], prehashed: bool) -> Result<Zeroizing<Vec<u8>>> {
    let md = super::rsa::digest(hash_id)?;
    if prehashed {
        if data.len() != md.size() {
            bail!("digest length mismatch");
        }
        Ok(Zeroizing::new(data.to_vec()))
    } else {
        Ok(Zeroizing::new(hash(md, data)?.to_vec()))
    }
}
/// ECDSA over the digest through EVP_PKEY_sign (DER ECDSA-Sig-Value).
pub fn sign(data: &[u8], hash_id: u32, message: &[u8], prehashed: bool) -> Result<Vec<u8>> {
    let key = private(data)?;
    let mut ctx = PkeyCtx::new(&key)?;
    ctx.sign_init()?;
    ctx.set_signature_md(md(hash_id)?)?;
    let mut out = vec![];
    ctx.sign_to_vec(&input(hash_id, message, prehashed)?, &mut out)?;
    Ok(out)
}
fn md(hash_id: u32) -> Result<&'static openssl::md::MdRef> {
    openssl::md::Md::from_nid(super::rsa::digest(hash_id)?.type_())
        .ok_or_else(|| anyhow::anyhow!("ECDSA digest unavailable"))
}
pub fn verify(
    data: &[u8],
    hash_id: u32,
    message: &[u8],
    prehashed: bool,
    signature: &[u8],
) -> Result<bool> {
    let key = public(data)?;
    let digest = input(hash_id, message, prehashed)?;
    match EcdsaSig::from_der(signature) {
        Ok(sig) if sig.to_der()?.as_slice() == signature => (),
        _ => return Ok(false),
    }
    let mut ctx = PkeyCtx::new(&key)?;
    ctx.verify_init()?;
    ctx.set_signature_md(md(hash_id)?)?;
    Ok(ctx.verify(&digest, signature).unwrap_or(false))
}
