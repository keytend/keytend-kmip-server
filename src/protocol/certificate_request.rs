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

//! The Certificate Request managed object (Object Type 0x0A).
//!
//! 2.0/2.1 section 2.2 and draft 3.0 section 2.2.2 define "A Managed
//! Cryptographic Object containing the Certificate Request" with the structure
//! Certificate Request Type (Enumeration) and Certificate Request Value (Byte
//! String). The 1.x Object Type enumeration has no such value, so these
//! objects do not exist for 1.x clients.
//!
//! The stored record keeps the registered bytes unchanged in `material`. The
//! Certificate Request Type is kept in `certificate_type`, so no new field is
//! persisted. The 2.x Key Format Type attribute is PKCS#10, the default for
//! this object (2.0 table 81, 2.1 table 81, 3.0 table 117).
use super::*;
use crate::crypto::issuance;
use openssl::x509::X509Req;

pub(super) const KIND: u32 = 10;
/// Key Format Type PKCS#10 (2.0/2.1 Key Format Type enumeration, 0x17).
pub(super) const PKCS10_FORMAT: u32 = 0x17;
const PKCS10: u32 = 2;
const PEM: u32 = 3;

/// Object Type Certificate Request first appears in 2.0 (2.0 table 430,
/// 2.1 table 468). 1.x refuses it like any other unknown object type.
pub(super) fn available(kind: u32, v: Version) -> R<()> {
    if kind == KIND && v.0 < 2 {
        return Err(fail(8, "Certificate Request objects require KMIP 2.0"));
    }
    Ok(())
}
/// A 1.x request never sees a Certificate Request, as 2.x never sees a Template.
pub(super) fn visible(obj: &Object, v: Option<Version>) -> bool {
    obj.object_type != KIND || v.is_none_or(|v| v.0 >= 2)
}
/// A request of the stated type, with a verified self-signature. CRMF (1) is
/// not implemented, and PGP (4) is Reserved from 2.0. Register's error list
/// has no Invalid CSR (2.1 table 294), so a bad request is Invalid Field.
fn parse(kind: u32, bytes: &[u8], invalid: Failure) -> R<X509Req> {
    if kind == 4 {
        return Err(fail(7, "Certificate Request Type is reserved"));
    }
    issuance::parse_request(kind, bytes).map_err(|e| match e {
        issuance::RequestError::Unsupported => {
            fail(8, "Only PKCS#10 and PEM certificate requests are supported")
        }
        issuance::RequestError::Invalid => invalid,
        issuance::RequestError::UnsupportedCurve => fail(8, "Unsupported EC curve"),
    })
}
/// The Register object: (Certificate Request Type, registered bytes).
pub(super) fn read(object: &Node) -> R<(u32, Vec<u8>)> {
    no_fields(
        object,
        &[CERTIFICATE_REQUEST_TYPE, CERTIFICATE_REQUEST_VALUE],
    )?;
    let kind = match object.required(CERTIFICATE_REQUEST_TYPE)?.value {
        Value::Enumeration(kind) => kind,
        _ => return Err(fail(7, "Certificate Request Type must be an Enumeration")),
    };
    let value = object
        .required(CERTIFICATE_REQUEST_VALUE)?
        .byte_string()?
        .to_vec();
    parse(
        kind,
        &value,
        fail(
            7,
            "Certificate Request is not a signed request of the specified type",
        ),
    )?;
    Ok((kind, value))
}
/// The stored request, for Certify and Re-certify. It was verified at Register.
pub(super) fn request(obj: &Object) -> R<X509Req> {
    parse(
        obj.certificate_type,
        &obj.material,
        fail(0x2f, "Stored Certificate Request is invalid"),
    )
}
/// The Get value. The only Key Format Type is PKCS#10. Asking for it explicitly
/// returns DER (type PKCS#10) even when the request was registered as PEM.
pub(super) fn value(obj: &Object, p: &Node) -> R<Node> {
    if p.get(KEY_WRAPPING_SPECIFICATION).is_some() {
        return Err(fail(8, "Certificate Request wrapping is not implemented"));
    }
    if p.get(KEY_COMPRESSION_TYPE).is_some() {
        return Err(fail(8, "Compression requires an EC public key"));
    }
    let (kind, bytes) = match p.get(KEY_FORMAT_TYPE) {
        None => (obj.certificate_type, obj.material.clone()),
        Some(n) if n.number()? == PKCS10_FORMAT => {
            if obj.certificate_type == PEM {
                (PKCS10, request(obj)?.to_der()?)
            } else {
                (obj.certificate_type, obj.material.clone())
            }
        }
        Some(_) => return Err(fail(0x10, "Key format conversion is not supported")),
    };
    Ok(Node::structure(
        CERTIFICATE_REQUEST,
        vec![
            Node::enumeration(CERTIFICATE_REQUEST_TYPE, kind),
            Node::bytes(CERTIFICATE_REQUEST_VALUE, bytes),
        ],
    ))
}
/// Draft 3.0 section 4.35.2 Certificate Request Link. It is "Reference or
/// Name Reference or Unique Identifier Enumeration or Integer"; the last two
/// forms are resolved to a Reference before validation. 2.x defines neither
/// this attribute nor a Link Type for it (2.1 table 465).
pub(super) fn validate_link(a: &Node, v: Version) -> R<()> {
    if v.0 < 3 {
        return Err(fail(8, "Attribute is not supported"));
    }
    match &a.value {
        Value::Reference(id) | Value::NameReference(id) if !id.is_empty() => Ok(()),
        _ => Err(fail(7, "Invalid Certificate Request Link")),
    }
}
/// The link stored on a certificate issued from a Certificate Request object.
/// Draft 3.0 4.35.2: such a certificate "SHALL have a Certificate Request
/// Link". It is kept in every version and projected only in draft 3.0.
pub(super) fn link(id: &str) -> Node {
    Node::reference(CERTIFICATE_REQUEST_LINK, id)
}
