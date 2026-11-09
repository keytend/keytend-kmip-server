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

//! End-entity X.509 issuance for Certify, Re-certify and Re-Provision. The
//! issuing CA certificate and private key, the subject and the alternative
//! names are always supplied by the caller; this module never selects a CA
//! and never issues CA certificates.
use anyhow::{Result, bail, ensure};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, PKeyRef, Private, Public},
    stack::Stack,
    x509::{
        GeneralNameRef, X509, X509NameRef, X509Ref, X509Req,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};

pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Validity of an issued certificate when the client asks for none, unless
/// the issuing CA expires earlier.
pub const DEFAULT_VALIDITY_SECONDS: i64 = 365 * 24 * 60 * 60;

/// The default notAfter: `validity` after `not_before`, cut short at the
/// issuing CA's notAfter.
pub fn default_not_after(not_before: i64, validity: i64, issuer_not_after: i64) -> i64 {
    not_before.saturating_add(validity).min(issuer_not_after)
}

#[derive(Debug, PartialEq, Eq)]
pub enum RequestError {
    /// CRMF and PGP requests are defined by KMIP but not implemented here.
    Unsupported,
    /// Not a self-signed request of the stated type.
    Invalid,
    /// An EC subject key on a curve the server does not support
    /// (`crate::crypto::ec::supported`).
    UnsupportedCurve,
}

/// Parse a PKCS#10 request (Certificate Request Type 2, DER) or a PEM request
/// (type 3) and verify its self-signature (proof of possession).
pub fn parse_request(kind: u32, bytes: &[u8]) -> std::result::Result<X509Req, RequestError> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(RequestError::Invalid);
    }
    let request = match kind {
        2 => {
            let request = X509Req::from_der(bytes).map_err(|_| RequestError::Invalid)?;
            // Reject trailing or non-canonical data, as for registered certificates.
            if request.to_der().ok().as_deref() != Some(bytes) {
                return Err(RequestError::Invalid);
            }
            request
        }
        3 => {
            let text = std::str::from_utf8(bytes).map_err(|_| RequestError::Invalid)?;
            let trimmed = text.trim();
            if !trimmed.starts_with("-----BEGIN CERTIFICATE REQUEST-----")
                || !trimmed.ends_with("-----END CERTIFICATE REQUEST-----")
                || trimmed.matches("-----BEGIN").count() != 1
            {
                return Err(RequestError::Invalid);
            }
            X509Req::from_pem(bytes).map_err(|_| RequestError::Invalid)?
        }
        1 | 4 => return Err(RequestError::Unsupported),
        _ => return Err(RequestError::Invalid),
    };
    // Decided from the DER, before OpenSSL decodes the key, so every build
    // refuses an unsupported curve alike.
    let der = request.to_der().map_err(|_| RequestError::Invalid)?;
    if crate::crypto::ec::request_curve(&der).is_some_and(|c| !crate::crypto::ec::supported(c)) {
        return Err(RequestError::UnsupportedCurve);
    }
    let key = request.public_key().map_err(|_| RequestError::Invalid)?;
    if !request.verify(&key).unwrap_or(false) {
        return Err(RequestError::Invalid);
    }
    Ok(request)
}

/// Supported subject keys: RSA of at least 2048 bits, or EC on P-256/384/521.
pub fn supported_subject_key(key: &PKeyRef<Public>) -> bool {
    match key.id() {
        Id::RSA => key.bits() >= 2048,
        Id::EC => key
            .ec_key()
            .ok()
            .and_then(|k| k.group().curve_name())
            .is_some_and(|n| [Nid::X9_62_PRIME256V1, Nid::SECP384R1, Nid::SECP521R1].contains(&n)),
        _ => false,
    }
}

/// Check that a stored CA certificate may issue now and return its notAfter.
pub fn check_issuer(ca: &X509Ref, key: &PKeyRef<Private>, at: i64) -> Result<i64> {
    let ca_public = ca.public_key()?;
    ensure!(
        key.public_eq(&ca_public),
        "Issuer private key does not match certificate"
    );
    let constraints = crate::crypto::certificate_attributes::ca_constraints(&ca.to_der()?)?;
    ensure!(constraints.ca, "Issuer certificate is not a CA");
    ensure!(
        constraints.key_cert_sign != Some(false),
        "Issuer key usage does not permit certificate signing"
    );
    let now = Asn1Time::from_unix(at)?;
    ensure!(
        ca.not_before() <= now && ca.not_after() > now,
        "Issuer certificate is outside its validity period"
    );
    asn1_unix(ca.not_after())
}

/// An ASN.1 time as Unix seconds.
pub fn asn1_unix(time: &openssl::asn1::Asn1TimeRef) -> Result<i64> {
    let epoch = Asn1Time::from_unix(0)?;
    let diff = epoch.diff(time)?;
    Ok(i64::from(diff.days) * 86_400 + i64::from(diff.secs))
}

/// Validity duration of an existing certificate, used when renewing it.
pub fn validity_seconds(cert: &X509Ref) -> Result<i64> {
    let duration = asn1_unix(cert.not_after())? - asn1_unix(cert.not_before())?;
    ensure!(duration > 0, "Certificate validity is empty");
    Ok(duration)
}

/// Subject alternative names supported for issuance, re-created from parsed
/// values rather than copied as opaque extension bytes.
fn alternative_names(names: &Stack<openssl::x509::GeneralName>) -> Result<Vec<(u8, String)>> {
    let mut out = vec![];
    for name in names {
        out.push(general_name(name)?);
    }
    Ok(out)
}
fn general_name(name: &GeneralNameRef) -> Result<(u8, String)> {
    if let Some(dns) = name.dnsname() {
        return Ok((0, dns.to_owned()));
    }
    if let Some(email) = name.email() {
        return Ok((1, email.to_owned()));
    }
    if let Some(uri) = name.uri() {
        return Ok((2, uri.to_owned()));
    }
    if let Some(ip) = name.ipaddress() {
        let text = match ip.len() {
            4 => std::net::Ipv4Addr::from(<[u8; 4]>::try_from(ip)?).to_string(),
            16 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(ip)?).to_string(),
            _ => bail!("Invalid IP subject alternative name"),
        };
        return Ok((3, text));
    }
    bail!("Unsupported subject alternative name type")
}

/// Alternative names requested by a CSR extension request, if any.
pub fn requested_alternative_names(request: &X509Req) -> Result<Vec<(u8, String)>> {
    let Ok(extensions) = request.extensions() else {
        return Ok(vec![]);
    };
    // Parse the requested extensions through a scratch certificate so that
    // only a well-formed subjectAltName is interpreted; other requested
    // extensions are ignored by issuance policy.
    let mut scratch = X509::builder()?;
    for extension in extensions {
        scratch.append_extension(extension)?;
    }
    match scratch.build().subject_alt_names() {
        Some(names) => alternative_names(&names),
        None => Ok(vec![]),
    }
}
pub fn certificate_alternative_names(cert: &X509Ref) -> Result<Vec<(u8, String)>> {
    match cert.subject_alt_names() {
        Some(names) => alternative_names(&names),
        None => Ok(vec![]),
    }
}

pub struct Issue<'a> {
    pub subject: &'a X509NameRef,
    pub alternative_names: &'a [(u8, String)],
    pub public_key: &'a PKeyRef<Public>,
    pub issuer: &'a X509Ref,
    pub issuer_key: &'a PKeyRef<Private>,
    pub issuer_not_after: i64,
    pub not_before: i64,
    /// Never later than `issuer_not_after`: callers refuse or cut short a
    /// later date first.
    pub not_after: i64,
    /// KMIP Cryptographic Usage Mask of the new certificate.
    pub usage: u32,
    /// Add the extended key usage clientAuth (TLS client certificates).
    pub client_auth: bool,
}

/// KMIP 1.4 table 96 / 2.1 section 4.15: X.509 Key Usage to Cryptographic Usage Mask.
fn key_usage(mask: u32) -> Result<Option<openssl::x509::X509Extension>> {
    const CERTIFICATE_SIGN: u32 = 0x1000;
    const CRL_SIGN: u32 = 0x2000;
    ensure!(
        mask & (CERTIFICATE_SIGN | CRL_SIGN) == 0,
        "Only end-entity certificates are issued"
    );
    let mut usage = KeyUsage::new();
    usage.critical();
    let mut any = false;
    if mask & 0x3 != 0 {
        usage.digital_signature();
        any = true;
    }
    if mask & 0x400 != 0 {
        usage.non_repudiation();
        any = true;
    }
    if mask & 0x30 != 0 {
        usage.key_encipherment();
        any = true;
    }
    if mask & 0xc != 0 {
        usage.data_encipherment();
        any = true;
    }
    if mask & 0x800 != 0 {
        usage.key_agreement();
        any = true;
    }
    Ok(if any { Some(usage.build()?) } else { None })
}

fn digest(key: &PKeyRef<Private>) -> Result<MessageDigest> {
    Ok(match key.id() {
        Id::RSA => MessageDigest::sha256(),
        Id::EC => match key.ec_key()?.group().curve_name() {
            Some(Nid::X9_62_PRIME256V1) => MessageDigest::sha256(),
            Some(Nid::SECP384R1) => MessageDigest::sha384(),
            Some(Nid::SECP521R1) => MessageDigest::sha512(),
            _ => bail!("Unsupported issuer curve"),
        },
        _ => bail!("Unsupported issuer key type"),
    })
}

/// Issue a version 3 end-entity certificate with a random 159-bit serial.
pub fn issue(request: &Issue) -> Result<Vec<u8>> {
    ensure!(
        supported_subject_key(request.public_key),
        "Unsupported subject public key"
    );
    ensure!(
        request.subject.entries().next().is_some() || !request.alternative_names.is_empty(),
        "An empty subject requires alternative names"
    );
    let not_after = request.not_after;
    ensure!(
        not_after <= request.issuer_not_after,
        "Validity ends after the issuer's"
    );
    ensure!(
        not_after > request.not_before,
        "Issuer validity is exhausted"
    );
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let mut serial = crate::crypto::random(20)?;
    serial[0] &= 0x7f;
    serial[0] |= 0x01;
    let serial = BigNum::from_slice(&serial)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(request.subject)?;
    builder.set_issuer_name(request.issuer.subject_name())?;
    builder.set_pubkey(request.public_key)?;
    let start = Asn1Time::from_unix(request.not_before)?;
    let end = Asn1Time::from_unix(not_after)?;
    builder.set_not_before(&start)?;
    builder.set_not_after(&end)?;
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    builder.append_extension(constraints.build()?)?;
    if let Some(usage) = key_usage(request.usage)? {
        builder.append_extension(usage)?;
    }
    if request.client_auth {
        builder.append_extension(ExtendedKeyUsage::new().client_auth().build()?)?;
    }
    if !request.alternative_names.is_empty() {
        let mut names = SubjectAlternativeName::new();
        if request.subject.entries().next().is_none() {
            names.critical();
        }
        for (kind, value) in request.alternative_names {
            match kind {
                0 => names.dns(value),
                1 => names.email(value),
                2 => names.uri(value),
                _ => names.ip(value),
            };
        }
        let extension = names.build(&builder.x509v3_context(Some(request.issuer), None))?;
        builder.append_extension(extension)?;
    }
    let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(ski)?;
    let aki = AuthorityKeyIdentifier::new()
        .keyid(false)
        .build(&builder.x509v3_context(Some(request.issuer), None))?;
    builder.append_extension(aki)?;
    builder.sign(request.issuer_key, digest(request.issuer_key)?)?;
    let cert = builder.build();
    let issuer_public = request.issuer.public_key()?;
    ensure!(
        cert.verify(&issuer_public)?,
        "Issued certificate does not verify"
    );
    Ok(cert.to_der()?)
}

pub fn public_key_from_der(der: &[u8]) -> Result<PKey<Public>> {
    Ok(PKey::public_key_from_der(der)?)
}
