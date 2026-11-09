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

//! Transparent RSA and DSA key formats (Key Format Types 8-11).
//!
//! The Key Material structures are identical in KMIP 1.0-1.4 (section
//! 2.1.7.2-2.1.7.5), 2.0/2.1 (sections 3.6-3.9) and 3.0 (sections 3.7-3.10).
//! Like the EC transparent forms (`ec.rs`), imported components are validated
//! and stored as DER (PKCS#1 for RSA, PKCS#8 / SubjectPublicKeyInfo for DSA),
//! while the Key Format Type records the registered format that Get returns
//! by default. DSA keys are registered and served; DSA signature generation is
//! not implemented (verification uses the stored public key).
use super::*;
use crate::crypto::transparent as engine;
use openssl::bn::BigNum;

pub(super) const RSA: u32 = 4;
pub(super) const DSA: u32 = 5;
pub(super) const DSA_PRIVATE: u32 = 8;
pub(super) const DSA_PUBLIC: u32 = 9;
pub(super) const RSA_PRIVATE: u32 = 10;
pub(super) const RSA_PUBLIC: u32 = 11;

pub(super) fn is_transparent(format: u32) -> bool {
    (DSA_PRIVATE..=RSA_PUBLIC).contains(&format)
}

/// The algorithm a transparent RSA/DSA format implies when the Key Block
/// omits Cryptographic Algorithm (Key Block: "MAY be omitted only if this
/// information is available from the Key Value").
pub(super) fn implied_algorithm(format: u32) -> Option<u32> {
    match format {
        DSA_PRIVATE | DSA_PUBLIC => Some(DSA),
        RSA_PRIVATE | RSA_PUBLIC => Some(RSA),
        _ => None,
    }
}

/// Whether this module validates registrations of the key: every DSA key, and
/// RSA keys in their transparent formats (PKCS#1/PKCS#8/X.509 RSA keys keep
/// the existing path).
pub(super) fn handles(kind: u32, alg: u32, format: u32) -> bool {
    matches!(kind, 3 | 4)
        && (alg == DSA || alg == RSA && matches!(format, RSA_PRIVATE | RSA_PUBLIC))
}

/// Imports per batch whose validation runs primality tests (every DSA key,
/// transparent RSA private keys) or RSA factor recovery; the same bound as
/// RSA key pair generation.
pub(super) const MAX_COSTLY_PER_BATCH: u32 = 4;
pub(super) fn costly(kind: u32, alg: u32, format: u32) -> bool {
    alg == DSA || kind == 4 && format == RSA_PRIVATE
}

/// Formats a stored RSA or DSA key can be registered in and served as.
pub(super) fn format_allowed(kind: u32, alg: u32, format: u32) -> bool {
    match (alg, kind) {
        (RSA, 3) => matches!(format, 3 | 5 | RSA_PUBLIC),
        (RSA, 4) => matches!(format, 3 | 4 | RSA_PRIVATE),
        (DSA, 3) => matches!(format, 5 | DSA_PUBLIC),
        (DSA, 4) => matches!(format, 4 | DSA_PRIVATE),
        _ => false,
    }
}

/// Table 81 (2.1) / 117 (3.0) Default Key Format Type for DSA keys.
pub(super) fn default_format(kind: u32) -> u32 {
    if kind == 4 { DSA_PRIVATE } else { DSA_PUBLIC }
}

fn big(km: &Node, tag: u32) -> R<Option<BigNum>> {
    let Some(n) = km.get(tag) else {
        return Ok(None);
    };
    let Value::BigInteger(bytes) = &n.value else {
        return Err(fail(7, "Key Material component must be a Big Integer"));
    };
    // Big Integers are two's complement, "padded with the minimal number of
    // leading sign-extended bytes to make the length a multiple of eight bytes"
    // (1.x section 9.1.1.4, 2.x/3.0 TTLV Item Value encoding); key components
    // are positive.
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) || bytes[0] & 0x80 != 0 {
        return Err(fail(
            7,
            "Key Material component must be a positive Big Integer",
        ));
    }
    BigNum::from_slice(bytes)
        .map(Some)
        .map_err(|_| fail(7, "Invalid Big Integer"))
}
fn required(km: &Node, tag: u32) -> R<BigNum> {
    big(km, tag)?.ok_or(fail(7, "Required Key Material component missing"))
}

/// Validates registered material and returns (stored DER, Cryptographic Length).
pub(super) fn import_material(kind: u32, alg: u32, format: u32, km: &Node) -> R<(Vec<u8>, u32)> {
    if !format_allowed(kind, alg, format) {
        return Err(fail(0x10, "Unsupported key format"));
    }
    let invalid = |what: &'static str| move |_| fail(7, what);
    Ok(match format {
        RSA_PUBLIC => {
            no_fields(km, &[MODULUS, PUBLIC_EXPONENT])?;
            engine::rsa_public(required(km, MODULUS)?, required(km, PUBLIC_EXPONENT)?)
                .map_err(invalid("Invalid RSA public key components"))?
        }
        RSA_PRIVATE => {
            no_fields(
                km,
                &[
                    MODULUS,
                    PRIVATE_EXPONENT,
                    PUBLIC_EXPONENT,
                    P,
                    Q,
                    PRIME_EXPONENT_P,
                    PRIME_EXPONENT_Q,
                    CRT_COEFFICIENT,
                ],
            )?;
            let parts = engine::RsaPrivate {
                n: Some(required(km, MODULUS)?),
                d: big(km, PRIVATE_EXPONENT)?,
                e: big(km, PUBLIC_EXPONENT)?,
                p: big(km, P)?,
                q: big(km, Q)?,
                dp: big(km, PRIME_EXPONENT_P)?,
                dq: big(km, PRIME_EXPONENT_Q)?,
                qinv: big(km, CRT_COEFFICIENT)?,
            };
            let (der, bits) = engine::rsa_private(parts)
                .map_err(invalid("Invalid RSA private key components"))?;
            (der.to_vec(), bits)
        }
        DSA_PUBLIC => {
            no_fields(km, &[P, Q, G, Y])?;
            engine::dsa_public(
                required(km, P)?,
                required(km, Q)?,
                required(km, G)?,
                required(km, Y)?,
            )
            .map_err(invalid("Invalid DSA public key components"))?
        }
        DSA_PRIVATE => {
            no_fields(km, &[P, Q, G, X])?;
            let (der, bits) = engine::dsa_private(
                required(km, P)?,
                required(km, Q)?,
                required(km, G)?,
                required(km, X)?,
            )
            .map_err(invalid("Invalid DSA private key components"))?;
            (der.to_vec(), bits)
        }
        _ => {
            // DSA in PKCS#8 or X.509 SubjectPublicKeyInfo.
            let der = km.byte_string()?;
            let bits = engine::dsa_der(der, kind == 4).map_err(invalid("Invalid DSA key"))?;
            (der.to_vec(), bits)
        }
    })
}

/// Minimal positive two's complement, padded to a multiple of 8 bytes.
fn encode(magnitude: &[u8]) -> Vec<u8> {
    let extra = usize::from(magnitude.first().is_none_or(|b| b & 0x80 != 0));
    let size = (magnitude.len() + extra).div_ceil(8) * 8;
    let mut bytes = vec![0; size];
    bytes[size - magnitude.len()..].copy_from_slice(magnitude);
    bytes
}

/// The Key Material for a Get or digest in `format`.
pub(super) fn key_material(obj: &Object, format: u32) -> R<Node> {
    if !is_transparent(format) {
        return Ok(Node::bytes(KEY_MATERIAL, obj.material.clone()));
    }
    let private = obj.object_type == 4;
    let tags: &[u32] = match format {
        RSA_PRIVATE => &[
            MODULUS,
            PRIVATE_EXPONENT,
            PUBLIC_EXPONENT,
            P,
            Q,
            PRIME_EXPONENT_P,
            PRIME_EXPONENT_Q,
            CRT_COEFFICIENT,
        ],
        RSA_PUBLIC => &[MODULUS, PUBLIC_EXPONENT],
        DSA_PRIVATE => &[P, Q, G, X],
        _ => &[P, Q, G, Y],
    };
    let parts = engine::components(&obj.material, obj.algorithm == DSA, private)
        .map_err(|_| fail(10, "Stored key cannot be converted"))?;
    Ok(Node::structure(
        KEY_MATERIAL,
        tags.iter()
            .zip(parts)
            .filter_map(|(tag, part)| {
                part.map(|m| Node {
                    tag: *tag,
                    value: Value::BigInteger(encode(&m)),
                })
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_integer_encoding_matches_kmip_padding() {
        assert_eq!(encode(&[0x7f]), vec![0, 0, 0, 0, 0, 0, 0, 0x7f]);
        assert_eq!(encode(&[0x80]), vec![0, 0, 0, 0, 0, 0, 0, 0x80]);
        assert_eq!(encode(&[0xff; 8]), [vec![0; 8], vec![0xff; 8]].concat());
        assert_eq!(encode(&[0x7f; 8]), vec![0x7f; 8]);
        assert_eq!(encode(&[]), vec![0; 8]);
    }

    #[test]
    fn formats_follow_algorithm_and_object_type() {
        assert!(format_allowed(3, RSA, RSA_PUBLIC) && !format_allowed(4, RSA, RSA_PUBLIC));
        assert!(format_allowed(4, DSA, DSA_PRIVATE) && !format_allowed(4, DSA, 3));
        assert!(!format_allowed(3, DSA, RSA_PUBLIC) && !format_allowed(3, RSA, DSA_PUBLIC));
        assert!(handles(4, DSA, 4) && handles(3, RSA, RSA_PUBLIC) && !handles(3, RSA, 5));
    }
}
