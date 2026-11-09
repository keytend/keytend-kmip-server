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

//! Versioned EC material formats and explicit ECDSA parameter semantics.
use super::*;
pub use crate::crypto::ec::EcCurves;

impl Engine {
    /// Elliptic curves KMIP operations may use (default: `nist`;
    /// docs/interpretations.md#supported-elliptic-curves): `extended` adds
    /// secp256k1 and brainpoolP256-512 r1/t1. FIPS mode keeps only the NIST
    /// curves in either setting.
    pub fn with_ec_curves(mut self, curves: EcCurves) -> Self {
        self.ec_curves = curves;
        self
    }
    pub fn ec_curves(&self) -> EcCurves {
        self.ec_curves
    }
}

pub(super) fn algorithm(alg: u32) -> bool {
    matches!(alg, 6 | 14 | 26)
}
pub(super) fn validate_algorithm(alg: u32, v: Version) -> R<()> {
    if !algorithm(alg) || alg == 26 && v < Version(1, 2) {
        return Err(fail(8, "EC algorithm is unavailable in this version"));
    }
    Ok(())
}
/// A Recommended Curve the server can use: KMIP 1.0/1.1 list only curves
/// 1-15; the server implements 13 curves
/// (docs/interpretations.md#supported-elliptic-curves), of which `crypto::ec::supported` offers the
/// NIST curves under `--ec-curves nist` (default) and all 13 under
/// `extended`; FIPS mode only the NIST curves in either setting.
pub(super) fn curve(curve: u32, v: Version) -> R<openssl::ec::EcGroup> {
    if curve > 15 && v < Version(1, 2) {
        return Err(fail(8, "Curve requires KMIP 1.2"));
    }
    // FIPS mode answers as it did before `--ec-curves` existed, under
    // either value: the FIPS refusal for an implemented curve comes first.
    if crypto::ec::implemented(curve) {
        fips_policy::curve(curve)?;
    }
    if !crypto::ec::supported(curve) {
        return Err(unsupported_curve());
    }
    crypto::ec::group(curve).map_err(|_| unsupported_curve())
}
fn unsupported_curve() -> Failure {
    fail(8, "Unsupported EC curve")
}
/// The curve of DER EC key material (Register, Import, a stored key before
/// it is used), read by the server itself so that a curve outside
/// `crypto::ec::supported` is refused alike whether or not the linked
/// OpenSSL could parse it. Material it cannot read is left to OpenSSL.
pub(super) fn der_curve(material: &[u8], v: Version) -> R<()> {
    if let Some(c) = crypto::ec::key_curve(material) {
        curve(c, v)?;
    }
    Ok(())
}
/// A stored EC key, before it signs, verifies, converts or is replaced.
pub(super) fn stored_curve(obj: &Object, v: Version) -> R<()> {
    der_curve(&obj.material, v)
}
/// An X.509 certificate with an EC subject key on an unsupported curve
/// (Register, Validate, signature verification with a certificate). Not a
/// FIPS check: FIPS mode stores certificates without one (docs/fips.md).
pub(super) fn certificate_curve(der: &[u8]) -> R<()> {
    match crypto::ec::certificate_curve(der) {
        Some(c) if !crypto::ec::supported(c) => Err(unsupported_curve()),
        _ => Ok(()),
    }
}
pub(super) fn domain(n: &Node, v: Version) -> R<()> {
    no_fields(n, &[RECOMMENDED_CURVE, QLENGTH])?;
    if let Some(c) = n.get(RECOMMENDED_CURVE) {
        if !matches!(c.value, Value::Enumeration(_)) {
            return Err(fail(7, "Recommended Curve must be an Enumeration"));
        }
        curve(c.number()?, v)?;
    }
    if let Some(q) = n.get(QLENGTH)
        && !matches!(q.value,Value::Integer(n) if n>0)
    {
        return Err(fail(7, "Qlength must be a positive Integer"));
    }
    Ok(())
}
pub(super) fn requested_curve(attrs: &[Node]) -> R<Option<u32>> {
    attrs
        .iter()
        .find(|a| a.tag == CRYPTOGRAPHIC_DOMAIN_PARAMETERS)
        .map(|a| {
            if a.get(QLENGTH).is_some() {
                return Err(fail(7, "Qlength is not an EC parameter"));
            }
            a.get(RECOMMENDED_CURVE)
                .map(Node::number)
                .transpose()
                .map_err(Into::into)
        })
        .transpose()
        .map(Option::flatten)
}
pub(super) fn take_format(attrs: &mut Vec<Node>, v: Version) -> R<Option<u32>> {
    let mut format = None;
    for a in attrs.iter().filter(|a| a.tag == KEY_FORMAT_TYPE) {
        if v.0 < 2 || !matches!(a.value, Value::Enumeration(_)) || format.is_some() {
            return Err(fail(7, "Invalid factory Key Format Type"));
        }
        format = Some(a.number()?);
    }
    attrs.retain(|a| a.tag != KEY_FORMAT_TYPE);
    Ok(format)
}
pub(super) fn default_format(kind: u32, alg: u32, v: Version) -> u32 {
    if v >= Version(1, 3) {
        if kind == 4 { 20 } else { 21 }
    } else if alg == 26 {
        if kind == 4 { 4 } else { 5 }
    } else if alg == 14 {
        if kind == 4 { 16 } else { 17 }
    } else if kind == 4 {
        14
    } else {
        15
    }
}
pub(super) fn format_allowed(kind: u32, alg: u32, format: u32, v: Version) -> bool {
    if !algorithm(alg) || alg == 26 && v < Version(1, 2) {
        return false;
    }
    match (kind, format) {
        (4, 4 | 6) | (3, 5) => true,
        (4, 20) | (3, 21) => v >= Version(1, 3),
        (4, 14) | (3, 15) => v.0 == 1 && alg == 6,
        (4, 16) | (3, 17) => v.0 == 1 && alg == 14,
        _ => false,
    }
}
/// Whether Get asks for an EC key in the form it is stored in: no format
/// conversion and no point compression.
pub(super) fn as_stored(obj: &Object, format: u32, compression: u32) -> bool {
    format == obj.format && compression == 1
}
/// A stored key's KMIP curve that KMIP operations cannot use now: an
/// extended curve under `--ec-curves nist`, or a curve removed in rc.3.
fn unusable_curve(obj: &Object) -> Option<u32> {
    crypto::ec::key_curve(&obj.material).filter(|c| *c != 0 && !crypto::ec::supported(*c))
}
/// Get of a stored EC key in its stored form. A key on a curve the server
/// does not offer now is still returned as stored, read from its DER
/// without curve arithmetic (docs/interpretations.md: keys stored under
/// `extended` and keys on removed curves stay retrievable as stored but
/// unusable). The KMIP 1.0/1.1 curve limit and FIPS mode apply as for every
/// other request.
pub(super) fn stored_form_curve(obj: &Object, v: Version) -> R<()> {
    let Some(c) = unusable_curve(obj) else {
        stored_curve(obj, v)?;
        let (c, _) = crypto::ec::info(&obj.material, obj.object_type == 4)?;
        return curve(c, v).map(drop);
    };
    if c > 15 && v < Version(1, 2) {
        return Err(fail(8, "Curve requires KMIP 1.2"));
    }
    if !crypto::ec::implemented(c) && crate::fips::active() {
        return Err(unsupported_curve());
    }
    fips_policy::curve(c)
}
/// The KMIP D of a positive scalar: a Big Integer padded to a multiple of 8
/// bytes, with a leading zero byte when the top bit is set.
fn d_node(scalar: &[u8]) -> Node {
    let extra = usize::from(scalar.first().is_some_and(|b| b & 0x80 != 0));
    let size = (scalar.len() + extra).div_ceil(8) * 8;
    let mut bytes = vec![0; size];
    bytes[size - scalar.len()..].copy_from_slice(scalar);
    Node {
        tag: D,
        value: Value::BigInteger(bytes),
    }
}
pub(super) fn key_material(obj: &Object, format: u32, compression: u32) -> R<Node> {
    if matches!(format, 14..=17 | 20 | 21) {
        if unusable_curve(obj).is_some() {
            // Only the stored form, read from the DER without OpenSSL
            // (`stored_form_curve`); anything else is refused.
            let (curve, value) = as_stored(obj, format, compression)
                .then(|| crypto::ec::stored_components(&obj.material, obj.object_type == 4))
                .flatten()
                .ok_or_else(unsupported_curve)?;
            let value = zeroize::Zeroizing::new(value);
            let value = if obj.object_type == 4 {
                d_node(&value)
            } else {
                Node::bytes(Q_STRING, value.to_vec())
            };
            return Ok(Node::structure(
                KEY_MATERIAL,
                vec![Node::enumeration(RECOMMENDED_CURVE, curve), value],
            ));
        }
        let (curve, _) = crypto::ec::info(&obj.material, obj.object_type == 4)
            .map_err(|_| fail(7, "Invalid EC key"))?;
        let value = if obj.object_type == 4 {
            d_node(&crypto::ec::scalar(&obj.material)?)
        } else {
            Node::bytes(
                Q_STRING,
                crypto::ec::point(&obj.material, compression)
                    .map_err(|_| fail(8, "Unsupported EC compression"))?,
            )
        };
        Ok(Node::structure(
            KEY_MATERIAL,
            vec![Node::enumeration(RECOMMENDED_CURVE, curve), value],
        ))
    } else {
        if compression != 1 {
            return Err(fail(8, "Compressed DER public key output is unsupported"));
        }
        Ok(Node::bytes(
            KEY_MATERIAL,
            if format == obj.format {
                obj.material.clone()
            } else {
                crypto::ec::export_der(&obj.material, obj.object_type == 4, format)?.to_vec()
            },
        ))
    }
}
pub(super) fn import_material(
    kind: u32,
    alg: u32,
    format: u32,
    material: &Node,
    attrs: &[Node],
    v: Version,
) -> R<(Vec<u8>, u32)> {
    if !format_allowed(kind, alg, format, v) {
        return Err(fail(0x10, "Unsupported EC key format"));
    }
    let clear = if matches!(format, 14..=17 | 20 | 21) {
        no_fields(
            material,
            &[RECOMMENDED_CURVE, if kind == 4 { D } else { Q_STRING }],
        )?;
        let c = material.required(RECOMMENDED_CURVE)?;
        if !matches!(c.value, Value::Enumeration(_)) {
            return Err(fail(7, "Recommended Curve must be an Enumeration"));
        }
        curve(c.number()?, v)?;
        if kind == 4 {
            let d = material.required(D)?;
            let Value::BigInteger(value) = &d.value else {
                return Err(fail(7, "EC D must be a Big Integer"));
            };
            if value.is_empty()
                || !value.len().is_multiple_of(8)
                || value.len() > 80
                || value[0] & 0x80 != 0
            {
                return Err(fail(7, "Invalid positive EC scalar"));
            }
            crypto::ec::import_scalar(c.number()?, value)
        } else {
            crypto::ec::import_point(c.number()?, material.required(Q_STRING)?.byte_string()?)
        }
    } else {
        der_curve(material.byte_string()?, v)?;
        crypto::ec::import_der(material.byte_string()?, kind == 4, format)
    }
    .map_err(|_| fail(7, "Invalid EC material"))?;
    let (actual, bits) =
        crypto::ec::info(&clear, kind == 4).map_err(|_| fail(7, "Invalid EC key"))?;
    curve(actual, v)?;
    if requested_curve(attrs)?.is_some_and(|c| c != actual) {
        return Err(fail(7, "EC curve disagrees with domain parameters"));
    }
    Ok((
        if matches!(format, 4..=6) {
            material.byte_string()?.to_vec()
        } else {
            clear.to_vec()
        },
        bits,
    ))
}
/// docs/interpretations.md#ecdsa-default-hash-in-kmip-13, KMIP 1.3 only: the
/// 1.3 text defines no ECDSA hash default, so SHA-256 is used, as the
/// OASIS trace CS-AC-M-3-ECC-13 expects. Signature Verify on an EC key
/// also ignores a Padding Method and an RSA Cryptographic Algorithm in the
/// parameters (that trace sends RSA/PSS parameters) and verifies with the
/// given hash; a different hash yields Validity Indicator Invalid. 1.4+ is
/// unchanged and still requires a hash.
fn lenient_1_3(v: Version) -> bool {
    v == Version(1, 3)
}
pub(super) fn hash_parameters(cp: &Node, v: Version, obj: &Object, verify: bool) -> R<u32> {
    let ignore_rsa = verify && lenient_1_3(v);
    let mut allowed = vec![
        CRYPTOGRAPHIC_ALGORITHM,
        HASHING_ALGORITHM,
        DIGITAL_SIGNATURE_ALGORITHM,
    ];
    if ignore_rsa {
        allowed.push(PADDING_METHOD);
    }
    no_fields(cp, &allowed)?;
    let algorithm = number(cp, CRYPTOGRAPHIC_ALGORITHM, obj.algorithm)?;
    if ![6, 26].contains(&algorithm) && !(ignore_rsa && algorithm == 4) {
        return Err(fail(7, "ECDSA algorithm mismatch"));
    }
    let combined = cp
        .get(DIGITAL_SIGNATURE_ALGORITHM)
        .map(Node::number)
        .transpose()?;
    let implied = match combined {
        Some(12..=16) => Some(combined.unwrap() - 8),
        None => None,
        _ => {
            return Err(fail(
                if v.0 >= 2 { 0x3e } else { 8 },
                "Unsupported ECDSA signature algorithm",
            ));
        }
    };
    let hash = match cp.get(HASHING_ALGORITHM) {
        Some(n) => n.number()?,
        None if implied.is_none() && lenient_1_3(v) => SHA256,
        None => implied.ok_or(fail(6, "ECDSA hashing algorithm required"))?,
    };
    if implied.is_some_and(|h| h != hash) {
        return Err(fail(7, "Conflicting ECDSA hash parameters"));
    }
    crypto::rsa::digest(hash).map_err(|_| fail(8, "Unsupported ECDSA hash"))?;
    fips_policy::ecdsa_hash(hash)?;
    stored_curve(obj, v)?;
    Ok(hash)
}
