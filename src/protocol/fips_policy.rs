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

//! FIPS mode hooks of the engine (docs/fips.md). Every check passes outside
//! FIPS mode. In FIPS mode a refused mechanism fails with the result reason
//! its operation already uses for an unsupported mechanism at that point, and
//! a Result Message that names FIPS mode; nothing else in the response
//! changes. The approved table itself is `crate::fips::approved`.
use super::*;
use crate::fips::{active, approved};

impl Engine {
    /// Refuse and stop advertising non-approved services (default: off).
    pub fn with_fips(mut self, enabled: bool) -> Self {
        self.fips = enabled;
        self
    }
    pub fn fips(&self) -> bool {
        self.fips
    }
}

/// Create Split Key (40) and Join Split Key (41): no NIST-approved secret
/// sharing scheme exists, so FIPS mode neither offers nor advertises them.
/// Encapsulate (65) and Decapsulate (66) are ML-KEM only, which the RHEL 9
/// FIPS provider 3.0.7 does not implement (pqc.rs).
pub(super) fn offers_operation(fips: bool, op: u32) -> bool {
    !(fips && matches!(op, 40 | 41 | pqc::ENCAPSULATE | pqc::DECAPSULATE))
}
/// Split Key objects (5) exist only for those operations.
pub(super) fn offers_object_type(fips: bool, kind: u32) -> bool {
    !(fips && kind == 5)
}
pub(super) fn object_type(kind: u32) -> R<()> {
    if !offers_object_type(active(), kind) {
        return Err(fail(8, "Split Key objects are not available in FIPS mode"));
    }
    Ok(())
}

/// A key algorithm label (Cryptographic Algorithm) usable in FIPS mode.
pub(super) fn algorithm(alg: u32) -> bool {
    !active() || approved::algorithm(alg)
}
/// Symmetric keys (Create, Register, Re-key, Derive Key): the reason
/// `validate_symmetric_parameters` gives an unsupported algorithm.
pub(super) fn symmetric_algorithm(alg: u32) -> R<()> {
    if !algorithm(alg) {
        return Err(fail(7, "Symmetric algorithm is not available in FIPS mode"));
    }
    Ok(())
}
/// Server-generated symmetric keys (Create, Re-key): HMAC keys of at least
/// 112 bits (SP 800-131A Rev. 2 section 10). Registering a shorter key is
/// storage, not generation; it can still verify but not generate a MAC.
pub(super) fn generated_symmetric(alg: u32, bits: u32) -> R<()> {
    if active()
        && crypto::authentication::hmac_hash(alg).is_some()
        && (bits as usize) < approved::MIN_KEY_BYTES * 8
    {
        return Err(fail(
            7,
            "HMAC keys shorter than 112 bits are not generated in FIPS mode",
        ));
    }
    Ok(())
}
/// Public and private keys (Register, Import): the reason the server gives
/// a public-key algorithm it does not implement.
pub(super) fn asymmetric_algorithm(kind: u32, alg: u32) -> R<()> {
    if matches!(kind, 3 | 4) && !algorithm(alg) {
        return Err(fail(
            8,
            "Public-key algorithm is not available in FIPS mode",
        ));
    }
    Ok(())
}
/// EC Recommended Curve (generation, domain parameters, import and key use,
/// through `ec::curve`): the reason it gives an unsupported curve.
pub(super) fn curve(curve: u32) -> R<()> {
    if active() && !approved::curve(curve) {
        return Err(fail(8, "EC curve is not available in FIPS mode"));
    }
    Ok(())
}
/// ChaCha20 and ChaCha20-Poly1305 keys in Encrypt and Decrypt: the reason
/// `cipher::setup` gives a key it cannot use.
pub(super) fn cipher_key(alg: u32) -> R<()> {
    if !algorithm(alg) {
        return Err(fail(8, "Cipher is not available in FIPS mode"));
    }
    Ok(())
}
/// AES-GCM in FIPS mode: tags of at least 96 bits (reported like any
/// unsupported tag length) and, for Encrypt, an IV the server generates
/// with the provider DRBG, of at least 96 bits (SP 800-38D section 8;
/// FIPS 140-3 IG C.H). A client-chosen encryption IV cannot be shown unique.
pub(super) fn gcm(encrypt: bool, tag_len: usize, client_iv: bool, generated_bits: u32) -> R<()> {
    if !active() {
        return Ok(());
    }
    if !approved::gcm_tag(tag_len) {
        // Reported like any unsupported tag length (cipher::unsupported_tag_length).
        return Err(fail(
            0x100,
            "AES-GCM tags shorter than 96 bits are not available in FIPS mode",
        ));
    }
    if encrypt && client_iv {
        return Err(fail(
            8,
            "FIPS mode encrypts AES-GCM only with a server-generated IV (Random IV)",
        ));
    }
    if encrypt && generated_bits < approved::MIN_GCM_RANDOM_IV_BITS {
        return Err(fail(
            7,
            "AES-GCM IVs shorter than 96 bits are not generated in FIPS mode",
        ));
    }
    Ok(())
}

fn unsupported_parameters(v: Version) -> Failure {
    fail(
        if v.0 >= 2 { 0x3e } else { 8 },
        "Cryptographic parameters are not available in FIPS mode",
    )
}
/// RSA signatures: generation needs a 2048-bit key, a SHA-2 or SHA-3 hash
/// and, for PSS, sLen <= hLen (FIPS 186-5 section 5.4); verification
/// also accepts 1024-bit keys and a SHA-1 MGF1 hash (legacy use), but not
/// a SHA-1 signature hash, which the RHEL 9 provider refuses.
pub(super) fn rsa_signature(
    parameters: &crypto::rsa::SignatureParameters,
    bits: u32,
    sign: bool,
    v: Version,
) -> R<()> {
    if !active() {
        return Ok(());
    }
    let ok = if sign {
        bits >= approved::MIN_RSA_BITS
            && approved::signature_hash(parameters.hash)
            && (!parameters.pss
                || crypto::rsa::digest(parameters.hash).is_ok_and(|d| {
                    approved::pss_salt(parameters.salt_len, d.size())
                        && approved::signature_hash(parameters.mgf_hash)
                }))
    } else {
        bits >= approved::MIN_RSA_VERIFY_BITS
            && approved::signature_hash(parameters.hash)
            && (!parameters.pss || approved::verification_mgf_hash(parameters.mgf_hash))
    };
    if !ok {
        return Err(unsupported_parameters(v));
    }
    Ok(())
}
/// RSA-OAEP key transport (Encrypt, Decrypt, key wrapping): 2048-bit keys
/// (SP 800-131A Rev. 2 section 6).
pub(super) fn rsa_transport(bits: u32) -> bool {
    !active() || bits >= approved::MIN_RSA_BITS
}
pub(super) fn rsa_encryption(bits: u32, v: Version) -> R<()> {
    if !rsa_transport(bits) {
        return Err(unsupported_parameters(v));
    }
    Ok(())
}
/// ECDSA: a SHA-2 or SHA-3 hash for generation and verification (the RHEL 9
/// provider refuses SHA-1 ECDSA in both).
pub(super) fn ecdsa_hash(hash: u32) -> R<()> {
    if active() && !approved::signature_hash(hash) {
        return Err(fail(8, "ECDSA hash is not available in FIPS mode"));
    }
    Ok(())
}
/// DSA verification: FIPS 186-5 retired DSA and the RHEL 9 provider has
/// none, so FIPS mode offers no DSA at all.
pub(super) fn dsa() -> R<()> {
    if active() {
        return Err(fail(8, "DSA is not available in FIPS mode"));
    }
    Ok(())
}
/// MAC: HMAC-MD5 is refused like any unsupported MAC algorithm, and MAC
/// generation needs a key of at least 112 bits (verification with a
/// shorter one is legacy use).
pub(super) fn mac(
    mechanism: crypto::authentication::Mechanism,
    key: &[u8],
    generate: bool,
) -> R<()> {
    if !active() {
        return Ok(());
    }
    if let crypto::authentication::Mechanism::Hmac(hash) = mechanism
        && (hash == 3 || generate && key.len() < approved::MIN_KEY_BYTES)
    {
        return Err(fail(8, "MAC is not available in FIPS mode"));
    }
    Ok(())
}
/// Derive Key: PBKDF2 and HKDF only, each with the SP 800-132 / SP 800-56C
/// lower bounds the provider enforces; the derivation's own reason for
/// unsupported parameters otherwise.
pub(super) fn derivation_method(method: u32, v: Version) -> R<()> {
    if active() && !approved::derivation_method(method) {
        return Err(fail(
            if v.0 >= 2 { 0x3e } else { 8 },
            "Derivation method is not available in FIPS mode",
        ));
    }
    Ok(())
}
pub(super) fn pbkdf2(
    password: usize,
    salt: usize,
    iterations: usize,
    output: usize,
    v: Version,
) -> R<()> {
    if active()
        && (password < approved::MIN_PBKDF2_PASSWORD_BYTES
            || salt < approved::MIN_PBKDF2_SALT_BYTES
            || iterations < approved::MIN_PBKDF2_ITERATIONS
            || output < approved::MIN_KEY_BYTES)
    {
        return Err(fail(
            if v.0 >= 2 { 0x3e } else { 8 },
            "PBKDF2 parameters are below the FIPS mode minimum",
        ));
    }
    Ok(())
}
pub(super) fn hkdf(key: usize, v: Version) -> R<()> {
    if active() && key < approved::MIN_KEY_BYTES {
        return Err(fail(
            if v.0 >= 2 { 0x3e } else { 8 },
            "HKDF keys shorter than 112 bits are not available in FIPS mode",
        ));
    }
    Ok(())
}
/// Certify and Re-certify: an RSA issuer key signs with 2048 bits or more.
pub(super) fn issuer_key<T: openssl::pkey::HasPublic>(key: &openssl::pkey::PKeyRef<T>) -> R<()> {
    if active() && key.id() == openssl::pkey::Id::RSA && key.bits() < approved::MIN_RSA_BITS {
        return Err(fail(
            8,
            "RSA issuer keys below 2048 bits cannot sign in FIPS mode",
        ));
    }
    Ok(())
}
