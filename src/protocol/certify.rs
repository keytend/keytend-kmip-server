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

//! Certify and Re-certify with a caller-designated issuing CA.
//!
//! KMIP leaves the certification authority to the server (1.0 section 4.6:
//! support "requires that the key management system have access to a
//! certification authority"). This server has no CA of its own. The request
//! designates the issuer with a Certificate Link attribute, whose meaning for
//! a Certificate object is "the parent certificate for a certificate in a
//! certificate chain" (2.1 section 11.28; 1.x Link Type definitions). The
//! signing key is reached through that CA certificate's Public Key Link and the
//! public key's Private Key Link. The CA certificate, both keys and the subject
//! public key must belong to the caller, and the private key must be Active
//! with the Certificate Sign usage. Only end-entity certificates are issued.
//!
//! Each issued certificate is a use of the CA private key: its Usage Limits
//! are charged like a Sign of the TBSCertificate (Object unit: one; Byte
//! unit: the TBSCertificate length) through the shared protection debit, so
//! a limit cannot be bypassed by certifying instead of signing. Certify and
//! Re-certify are refused in Undo batches (`refused_under_undo`).
use super::*;
use crate::crypto::issuance;
use openssl::{
    pkey::{PKey, Private, Public},
    x509::{X509, X509Req},
};

const CERTIFICATE_SIGN: u32 = 0x1000;

fn request_value_tag(v: Version) -> u32 {
    // 1.x "Certificate Request" (0x420018); 2.0+ "Certificate Request Value" (0x420140).
    if v.0 == 1 {
        CERTIFICATE_REQUEST
    } else {
        CERTIFICATE_REQUEST_VALUE
    }
}
/// 1.0-1.4 Certify/Re-certify errors: a request that is not a signed request
/// of the stated type is Invalid Field. 2.0+ adds Invalid CSR (0x2F).
fn invalid_request(v: Version) -> Failure {
    fail(
        if v.0 >= 2 { 0x2f } else { 7 },
        "Certificate Request is not a signed request of the specified type",
    )
}
/// 1.x: "Object specified is not able to be certified" is Permission Denied;
/// 2.0+ lists Invalid Object Type (0x30).
fn wrong_type(v: Version) -> Failure {
    fail(
        if v.0 >= 2 { 0x30 } else { 12 },
        "Object type cannot be certified",
    )
}
fn not_certifiable(message: &'static str) -> Failure {
    fail(12, message)
}
/// Certify (6) and Re-certify (7) are refused with Feature Not Supported in a
/// batch whose Batch Error Continuation Option is Undo. An issued certificate
/// is signed by the CA and leaves in the response; an Undone item keeps its
/// response (1.4 table 366; 2.1 table 424 "Operation Undone": "The requested
/// operation was performed, but had to be undone"), so a rollback would leave
/// a valid CA-signed certificate the server has no record of and cannot
/// revoke. Feature Not Supported is listed for both operations (1.4 General
/// Errors table 327; 2.1 tables 181 and 302; draft 3.0 tables 269 and 411).
///
/// Re-Provision (53) is refused for the same reason, and because its
/// replacement of the client certificate takes effect at the commit of its
/// message (provisioning.rs).
pub(super) fn refused_under_undo(op: u32, continuation: u32) -> Option<Failure> {
    (continuation == 3 && matches!(op, 6 | 7 | 53)).then(|| {
        fail(
            8,
            "Certify, Re-certify and Re-Provision are not supported in Undo batches",
        )
    })
}
/// The length of the TBSCertificate inside a DER Certificate: the bytes the
/// CA key signed.
fn tbs_len(der: &[u8]) -> usize {
    fn header(der: &[u8], at: usize) -> Option<(usize, usize)> {
        let first = *der.get(at + 1)?;
        if first < 0x80 {
            return Some((2, usize::from(first)));
        }
        let count = usize::from(first & 0x7f);
        let mut len = 0usize;
        for i in 0..count {
            len = len.checked_mul(256)? + usize::from(*der.get(at + 2 + i)?);
        }
        Some((2 + count, len))
    }
    header(der, 0)
        .and_then(|(outer, _)| header(der, outer).map(|(h, len)| h + len))
        .unwrap_or(der.len())
}
/// `optional`: the operation may omit the Certificate Request Type and value
/// together (2.x Certify and Re-certify; 1.1-1.4 Re-certify).
fn read_request(p: &Node, v: Version, optional: bool) -> R<Option<X509Req>> {
    let kind = p.get(CERTIFICATE_REQUEST_TYPE);
    let value = p.get(request_value_tag(v));
    let (kind, value) = match (kind, value) {
        (None, None) if optional => return Ok(None),
        (Some(kind), Some(value)) => (kind, value),
        // 1.0 table 124 requires both fields; 1.1-1.4 (1.4 table 184) and
        // 2.x let both be omitted but require the type whenever a request
        // value is present.
        _ => return Err(fail(7, "Certificate Request Type and value are required")),
    };
    let kind = match kind.value {
        Value::Enumeration(kind) => kind,
        _ => return Err(fail(7, "Certificate Request Type must be an Enumeration")),
    };
    if v.0 >= 2 && kind == 4 {
        // PGP (4) is Reserved from 2.0 onward.
        return Err(fail(7, "Certificate Request Type is reserved"));
    }
    match issuance::parse_request(kind, value.byte_string()?) {
        Ok(request) => Ok(Some(request)),
        Err(issuance::RequestError::Unsupported) => Err(fail(
            8,
            "Only PKCS#10 and PEM certificate requests are supported",
        )),
        Err(issuance::RequestError::Invalid) => Err(invalid_request(v)),
        Err(issuance::RequestError::UnsupportedCurve) => Err(fail(8, "Unsupported EC curve")),
    }
}
/// Attributes that are derived from the issued certificate. The Certificate
/// Request takes precedence over conflicting requested attributes (1.0 4.6,
/// 2.1 6.1.6), and the certificate itself determines these values.
fn derived(tag: u32) -> bool {
    certificate::owned_attribute(tag)
        || matches!(tag, CRYPTOGRAPHIC_ALGORITHM | CRYPTOGRAPHIC_LENGTH)
}
/// Requested Activation Date (the certificate's notBefore) and Deactivation
/// Date (its notAfter) of a Certify or Re-certify request.
type Requested = (Option<i64>, Option<i64>);
fn requested_dates(attrs: &[Node]) -> Requested {
    (
        attr_time(attrs, ACTIVATION_DATE),
        attr_time(attrs, DEACTIVATION_DATE),
    )
}
/// A request error, checked before the issuer is resolved: the certificate
/// would end at or before it starts. Invalid Field, which every edition
/// lists for Certify and Re-certify (docs/certificates.md#validity-period).
fn check_order((activation, deactivation): Requested, at: i64) -> R<()> {
    if let Some(deactivation) = deactivation
        && deactivation <= activation.unwrap_or(at)
    {
        return Err(fail(
            7,
            "The Deactivation Date (notAfter) must be later than the Activation Date (notBefore)",
        ));
    }
    Ok(())
}
/// The certificate's notBefore and notAfter. Without a Deactivation Date the
/// certificate lasts `default` from its notBefore, cut short at the CA's
/// notAfter; a requested date past the CA's notAfter is refused instead.
fn period(requested: Requested, at: i64, default: i64, issuer_not_after: i64) -> R<(i64, i64)> {
    let (activation, deactivation) = requested;
    if activation.is_some_and(|a| a >= issuer_not_after)
        || deactivation.is_some_and(|d| d > issuer_not_after)
    {
        return Err(fail(
            7,
            "The requested validity ends after the issuing CA's notAfter",
        ));
    }
    check_order(requested, at)?;
    let not_before = activation.unwrap_or(at);
    let not_after = deactivation
        .unwrap_or_else(|| issuance::default_not_after(not_before, default, issuer_not_after));
    if not_after <= not_before {
        return Err(not_certifiable("Issuer cannot sign certificates now"));
    }
    Ok((not_before, not_after))
}
/// With explicit dates the stored certificate has only the dates the request
/// gives, as given: a request without an Activation Date leaves it
/// Pre-Active, whatever the certificate's notBefore, so a client can activate
/// it once its key and links are in place. Re-certify copies no other date
/// from the existing certificate.
fn requested_only(attrs: &mut Vec<Node>, (activation, deactivation): Requested) {
    attrs.retain(|a| ![ACTIVATION_DATE, DEACTIVATION_DATE].contains(&a.tag));
    attrs.extend(activation.map(|d| Node::date(ACTIVATION_DATE, d)));
    attrs.extend(deactivation.map(|d| Node::date(DEACTIVATION_DATE, d)));
}
fn issuer_links(attrs: &[Node]) -> R<Vec<String>> {
    attrs
        .iter()
        .filter(|a| link_kind(a) == Some(0x101))
        .map(|a| {
            Ok(a.required(LINKED_OBJECT_IDENTIFIER)?
                .identifier_text()?
                .to_owned())
        })
        .collect()
}
fn public_key(obj: &Object) -> R<PKey<Public>> {
    let der = if obj.algorithm == 4 {
        crypto::rsa::export(&obj.material, false, 5).map_err(|_| fail(7, "Invalid public key"))?
    } else {
        zeroize::Zeroizing::new(obj.material.clone())
    };
    issuance::public_key_from_der(&der).map_err(|_| fail(7, "Invalid public key"))
}
fn link_target(obj: &Object, kind: u32) -> R<Option<String>> {
    let links = obj
        .attrs
        .iter()
        .filter(|a| link_kind(a) == Some(kind))
        .collect::<Vec<_>>();
    match links.as_slice() {
        [] => Ok(None),
        [link] => Ok(Some(
            link.required(LINKED_OBJECT_IDENTIFIER)?
                .identifier_text()?
                .to_owned(),
        )),
        _ => Err(not_certifiable("Issuer key links are ambiguous")),
    }
}
struct Issuer {
    id: String,
    certificate: X509,
    key: PKey<Private>,
    not_after: i64,
    /// The CA private key object, charged for each issued certificate.
    private: Object,
}
impl Engine {
    /// A caller-owned object; grants never make another owner's CA usable.
    fn own(&self, owner: &str, id: &str) -> R<Object> {
        let mut obj = self.store.get(owner, id)?.ok_or_else(not_found::object)?;
        metadata::hydrate(&mut obj)?;
        apply_dates(&mut obj);
        archive::online(&obj)?;
        Ok(obj)
    }
    /// A caller-owned Certificate Request object, used in place of an inline
    /// request. Supplying both leaves two requests for one certificate (only a
    /// single certificate is requested at a time, 2.1 6.1.6), so it is refused.
    fn stored_request(&self, owner: &str, obj: &Object, inline: bool) -> R<X509Req> {
        if inline {
            return Err(fail(
                7,
                "Give the Certificate Request either inline or by identifier",
            ));
        }
        if obj.owner != owner {
            return Err(not_certifiable(
                "The Certificate Request must belong to the caller",
            ));
        }
        if !matches!(obj.state, 1 | 2) {
            return Err(not_certifiable(
                "Certificate Request state does not permit certification",
            ));
        }
        certificate_request::request(obj)
    }
    fn issuer(&self, owner: &str, v: Version, id: &str, at: i64) -> R<Issuer> {
        let ca = self.own(owner, id)?;
        if ca.object_type != 1 || ca.certificate_type != 1 || ca.material.is_empty() {
            return Err(not_certifiable("Issuer must be an X.509 certificate"));
        }
        if ca.state != 2 {
            return Err(not_certifiable("Issuer certificate is not Active"));
        }
        let certificate = X509::from_der(&ca.material)?;
        let public_id = link_target(&ca, 0x102)?
            .ok_or(not_certifiable("Issuer certificate has no Public Key Link"))?;
        let public = self.own(owner, &public_id)?;
        let private_id = link_target(&public, 0x103)?
            .ok_or(not_certifiable("Issuer public key has no Private Key Link"))?;
        let mut private = self.own(owner, &private_id)?;
        if public.object_type != 3 || private.object_type != 4 {
            return Err(not_certifiable("Issuer key links do not form a key pair"));
        }
        self.materialize(owner, &mut private)?;
        // The signing key must be Active and permit Certificate Sign (usage
        // mapping for keyCertSign: 1.4 table 96, 2.1 section 4.15).
        check_use(&private, v, CERTIFICATE_SIGN, true)?;
        let key = openssl::pkey::PKey::private_key_from_der(&private.material)
            .map_err(|_| fail(7, "Invalid issuer private key"))?;
        fips_policy::issuer_key(&key)?;
        let not_after = issuance::check_issuer(&certificate, &key, at)
            .map_err(|_| not_certifiable("Issuer cannot sign certificates now"))?;
        Ok(Issuer {
            id: ca.id.clone(),
            certificate,
            key,
            not_after,
            private,
        })
    }
    /// Charge the CA private key's Usage Limits for one issued certificate,
    /// recorded for Undo like every protection debit (usage.rs). Exhaustion
    /// is Permission Denied, which every version lists for both operations.
    fn charge_issuer(&self, issuer: &mut Issuer, der: &[u8], v: Version) -> R<()> {
        self.consume_protection(&mut issuer.private, tbs_len(der), v, 12)
    }
    #[allow(clippy::too_many_arguments)]
    fn issue_certificate(
        &self,
        issuer: &Issuer,
        subject: &openssl::x509::X509NameRef,
        names: &[(u8, String)],
        public: &PKey<Public>,
        (not_before, not_after): (i64, i64),
        usage: u32,
    ) -> R<Vec<u8>> {
        if !issuance::supported_subject_key(public) {
            return Err(fail(8, "Subject key must be RSA-2048+ or EC P-256/384/521"));
        }
        if usage & (CERTIFICATE_SIGN | 0x2000) != 0 {
            return Err(not_certifiable("Only end-entity certificates are issued"));
        }
        if subject.entries().next().is_none() && names.is_empty() {
            return Err(fail(7, "An empty subject requires alternative names"));
        }
        issuance::issue(&issuance::Issue {
            subject,
            alternative_names: names,
            public_key: public,
            issuer: &issuer.certificate,
            issuer_key: &issuer.key,
            issuer_not_after: issuer.not_after,
            not_before,
            not_after,
            usage,
            client_auth: false,
        })
        .map_err(|e| {
            tracing::warn!(error=%e, "certificate issuance failed");
            fail(10, "Certificate issuance failed")
        })
    }
    pub(super) fn certify(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        let mut allowed = vec![
            UNIQUE_IDENTIFIER,
            CERTIFICATE_REQUEST_TYPE,
            request_value_tag(v),
        ];
        if v.0 == 1 {
            allowed.push(TEMPLATE_ATTRIBUTE);
        } else {
            allowed.extend([ATTRIBUTES, PROTECTION_STORAGE_MASKS]);
        }
        no_fields(p, &allowed)?;
        protection::select(p, v)?;
        let mut request = read_request(p, v, v >= Version(1, 1))?;
        let mut request_object = None;
        // 1.x: the ID Placeholder stands in for an omitted Unique Identifier.
        // 2.0+: it does so only when no Certificate Request is present; with a
        // request and no identifier, the request alone names the public key.
        let key = if v.0 == 1 || p.get(UNIQUE_IDENTIFIER).is_some() || request.is_none() {
            let key = self.object(owner, p, placeholder)?;
            // 2.0 table 164, 2.1 table 179, draft 3.0 table 267: the identifier names
            // "the Public Key or the Certificate Request being certified".
            if key.object_type == certificate_request::KIND {
                request = Some(self.stored_request(owner, &key, request.is_some())?);
                request_object = Some(key.id.clone());
                None
            } else {
                Some(key)
            }
        } else {
            None
        };
        let key = if let Some(mut key) = key {
            if key.object_type != 3 {
                return Err(wrong_type(v));
            }
            if key.owner != owner {
                return Err(not_certifiable("The public key must belong to the caller"));
            }
            if !matches!(key.state, 1 | 2) {
                return Err(not_certifiable(
                    "Public key state does not permit certification",
                ));
            }
            self.materialize(owner, &mut key)?;
            Some(key)
        } else {
            None
        };
        let Some(request) = request else {
            // 1.1+ permits omitting the request (1.4 section 4.7, 2.1
            // section 6.1.6), but then nothing defines the subject name; this
            // server does not invent one. Feature Not Supported is listed for
            // Certify in 2.0 table 166 and 2.1 table 181.
            return Err(fail(
                8,
                "Certify without a Certificate Request is not supported",
            ));
        };
        let requested = request.public_key().map_err(|_| invalid_request(v))?;
        let public = match &key {
            Some(key) => {
                let stored = public_key(key)?;
                if !stored.public_eq(&requested) {
                    return Err(fail(
                        7,
                        "Certificate Request key does not match the Public Key",
                    ));
                }
                stored
            }
            None => requested,
        };
        let mut attrs = read_attrs(p, v)?;
        // Request errors of the 1.x Certify table (1.4 Table 334) come
        // before the issuer is resolved.
        validate_attrs(&attrs, v)?;
        let at = now();
        let requested = requested_dates(&attrs);
        check_order(requested, at)?;
        if attrs
            .iter()
            .any(|a| link_kind(a).is_some_and(|kind| [0x102, 0x103, 0x106, 0x107].contains(&kind)))
        {
            return Err(fail(
                7,
                "Certificate key and replacement links are assigned by the server",
            ));
        }
        let issuer_id = match issuer_links(&attrs)?.as_slice() {
            [id] => id.clone(),
            [] => {
                return Err(not_certifiable(
                    "Certify requires a Certificate Link to a caller-owned issuing CA certificate",
                ));
            }
            _ => return Err(fail(7, "Only one issuing CA certificate may be designated")),
        };
        let mut issuer = self.issuer(owner, v, &issuer_id, at)?;
        let period = period(
            requested,
            at,
            issuance::DEFAULT_VALIDITY_SECONDS,
            issuer.not_after,
        )?;
        attrs.retain(|a| !derived(a.tag));
        if requested != (None, None) {
            requested_only(&mut attrs, requested);
        }
        let usage = match attrs.iter().find(|a| a.tag == CRYPTOGRAPHIC_USAGE_MASK) {
            Some(_) => attr_num(&attrs, CRYPTOGRAPHIC_USAGE_MASK, 0)?,
            None => {
                let usage = key.as_ref().map_or(0, |k| k.usage);
                attrs.push(Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage as i32));
                usage
            }
        };
        let names = issuance::requested_alternative_names(&request)
            .map_err(|_| fail(7, "Unsupported requested subject alternative name"))?;
        let der = self.issue_certificate(
            &issuer,
            request.subject_name(),
            &names,
            &public,
            period,
            usage,
        )?;
        self.charge_issuer(&mut issuer, &der, v)?;
        // Legacy (< 1.2) EC certificates need the stored key's algorithm.
        if let Some(key) = &key
            && ec::algorithm(key.algorithm)
        {
            attrs.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, key.algorithm));
        }
        let mut obj = self.build_certificate(owner, v, p, der, attrs)?;
        if let Some(key) = &key {
            attributes::append(&mut obj, object_link(0x102, &key.id))?;
        }
        if let Some(id) = &request_object {
            attributes::append(&mut obj, certificate_request::link(id))?;
        }
        self.unique_names(&obj, v)?;
        self.store.insert(&obj)?;
        // 1.0 4.6: "the Link attribute of the Public Key and of the generated
        // certificate SHALL be set to point at each other" (2.1 6.1.6).
        if let Some(mut key) = key {
            attributes::append(&mut key, object_link(0x101, &obj.id))?;
            key.updated = at;
            self.store.put(&key)?;
        }
        tracing::info!(issuer=%issuer.id, certificate=%obj.id, "certificate issued");
        *placeholder = Some(obj.id.clone());
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
    /// Store an issued certificate through the Register path, so attribute
    /// validation, derived X.509 metadata, digest and dates are shared.
    fn build_certificate(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        der: Vec<u8>,
        attrs: Vec<Node>,
    ) -> R<Object> {
        let mut fields = vec![
            Node::enumeration(OBJECT_TYPE, 1),
            Node::structure(
                CERTIFICATE,
                vec![
                    Node::enumeration(CERTIFICATE_TYPE, 1),
                    Node::bytes(CERTIFICATE_VALUE, der),
                ],
            ),
        ];
        if v.0 == 1 {
            fields.push(Node::structure(
                TEMPLATE_ATTRIBUTE,
                attrs.iter().map(encode_attribute).collect::<R<Vec<_>>>()?,
            ));
        } else {
            fields.push(Node::structure(ATTRIBUTES, attrs));
            if let Some(masks) = p.get(PROTECTION_STORAGE_MASKS) {
                fields.push(masks.clone());
            }
        }
        let mut obj =
            self.build_object(owner, v, &Node::structure(REQUEST_PAYLOAD, fields), true)?;
        // The server generated this certificate (serial from the provider RNG).
        metadata::initialize(&mut obj, v, true)?;
        Ok(obj)
    }
    pub(super) fn recertify(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        let mut allowed = vec![
            UNIQUE_IDENTIFIER,
            CERTIFICATE_REQUEST_TYPE,
            request_value_tag(v),
            OFFSET,
        ];
        if v.0 == 1 {
            allowed.push(TEMPLATE_ATTRIBUTE);
        } else {
            allowed.extend([
                ATTRIBUTES,
                PROTECTION_STORAGE_MASKS,
                CERTIFICATE_REQUEST_UNIQUE_IDENTIFIER,
            ]);
        }
        no_fields(p, &allowed)?;
        if v.0 >= 3 && p.get(UNIQUE_IDENTIFIER).is_none() {
            return Err(fail(6, "Unique Identifier is required in draft 3.0"));
        }
        let protection_mask = protection::select(p, v)?;
        // 1.1-1.4 section 4.8: "The Certificate Request object MAY be
        // omitted"; without it (and without a Certificate Type attribute) the
        // new certificate keeps the existing certificate's type, here X.509.
        // The 1.x request tables mark the request REQUIRED; the prose is
        // followed. 1.0 4.7 does not allow the omission.
        let mut request = read_request(p, v, v >= Version(1, 1))?;
        // 2.0 table 274, 2.1 table 300, draft 3.0 table 409: Certificate Request Unique
        // Identifier, "The Unique Identifier of the Certificate Request".
        let request_object = match p.get(CERTIFICATE_REQUEST_UNIQUE_IDENTIFIER) {
            Some(n) => {
                let id = n.identifier_text()?;
                let obj = self.own(owner, id)?;
                if obj.object_type != certificate_request::KIND {
                    return Err(wrong_type(v));
                }
                request = Some(self.stored_request(owner, &obj, request.is_some())?);
                Some(obj.id.clone())
            }
            None => None,
        };
        let mut old = self.object(owner, p, placeholder)?;
        if old.object_type != 1 || old.certificate_type != 1 {
            return Err(wrong_type(v));
        }
        if old.owner != owner {
            return Err(not_certifiable("The certificate must belong to the caller"));
        }
        rekey::eligible(&old, v)?;
        let existing = X509::from_der(&old.material).map_err(|_| fail(7, "Invalid certificate"))?;
        let public = existing.public_key()?;
        // 1.0 4.7 / 2.1 6.1.45: renew "an existing certificate for the same key pair".
        let (subject, names) = match &request {
            Some(request) => {
                let requested = request.public_key().map_err(|_| invalid_request(v))?;
                if !requested.public_eq(&public) {
                    return Err(fail(
                        7,
                        "Re-certify renews a certificate for the same key pair",
                    ));
                }
                (
                    request.subject_name().to_owned()?,
                    issuance::requested_alternative_names(request)
                        .map_err(|_| fail(7, "Unsupported requested subject alternative name"))?,
                )
            }
            None => (
                existing.subject_name().to_owned()?,
                issuance::certificate_alternative_names(&existing)
                    .map_err(|_| fail(8, "Existing alternative names cannot be renewed"))?,
            ),
        };
        let mut overrides = read_attrs(p, v)?;
        // Request errors of the 1.x Re-certify table (1.4 Table 335) come
        // before the issuer is resolved: invalid attributes, and an Offset
        // given with an Activation or Deactivation Date (Invalid Message).
        validate_attrs(&overrides, v)?;
        if rekey::offset(p)?.is_some()
            && overrides
                .iter()
                .any(|a| [ACTIVATION_DATE, DEACTIVATION_DATE].contains(&a.tag))
        {
            return Err(fail(
                4,
                "Offset and explicit lifecycle dates cannot be combined",
            ));
        }
        let at = now();
        let requested = requested_dates(&overrides);
        check_order(requested, at)?;
        overrides.retain(|a| !derived(a.tag));
        let issuer_id = match issuer_links(&overrides)?.as_slice() {
            [id] => id.clone(),
            [] => match issuer_links(&old.attrs)?.as_slice() {
                [id] => id.clone(),
                _ => {
                    return Err(not_certifiable(
                        "Re-certify requires one Certificate Link to a caller-owned issuing CA",
                    ));
                }
            },
            _ => return Err(fail(7, "Only one issuing CA certificate may be designated")),
        };
        let public_key_id = link_target(&old, 0x102)?;
        let mut issuer = self.issuer(owner, v, &issuer_id, at)?;
        // Table 127 (1.0) / 299 (2.1): copy the existing attributes except
        // the listed ones; Offset shifts Activation and Deactivation Date.
        // Certificate-derived metadata is stored version-neutrally and is
        // re-derived from the new certificate below.
        let mut source = old.clone();
        // Links are not copied (rekey::replacement drops Link); likewise a
        // copied Certificate Request Link would claim the new certificate came
        // from the old certificate's request.
        source
            .attrs
            .retain(|a| !derived(a.tag) && a.tag != CERTIFICATE_REQUEST_LINK);
        let mut obj = rekey::replacement(
            &source,
            overrides,
            v,
            at,
            rekey::offset(p)?,
            &[ACTIVATION_DATE, DEACTIVATION_DATE],
            self.maximum_lease,
        )?;
        // Without explicit dates the new certificate keeps the existing
        // one's length from now, and the object's dates follow the copy or
        // Offset rules (rekey::replacement).
        let validity = issuance::validity_seconds(&existing)
            .map_err(|_| fail(7, "Existing certificate validity is invalid"))?;
        let period = period(requested, at, validity, issuer.not_after)?;
        if requested != (None, None) {
            requested_only(&mut obj.attrs, requested);
        }
        let der = self.issue_certificate(&issuer, &subject, &names, &public, period, obj.usage)?;
        self.charge_issuer(&mut issuer, &der, v)?;
        if ec::algorithm(old.algorithm) {
            obj.attrs
                .push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, old.algorithm));
        }
        let (algorithm, bits) = certificate::prepare(1, &der, &mut obj.attrs, v)?;
        obj.material = der;
        obj.format = 0;
        obj.algorithm = algorithm;
        obj.bits = bits;
        obj.protection_mask = protection_mask;
        if !obj.attrs.iter().any(|a| link_kind(a) == Some(0x101)) {
            attributes::append(&mut obj, object_link(0x101, &issuer.id))?;
        }
        if let Some(id) = &public_key_id {
            attributes::append(&mut obj, object_link(0x102, id))?;
        }
        if let Some(id) = &request_object {
            attributes::append(&mut obj, certificate_request::link(id))?;
        }
        rekey::finish(&mut old, &mut obj)?;
        self.store.put(&old)?;
        // "The Link attribute of the Public Key is changed to point to the
        // new certificate" (1.0 4.7; 2.1 6.1.45).
        if let Some(id) = public_key_id {
            let mut key = self.own(owner, &id)?;
            let mut changed = false;
            for link in key.attrs.iter_mut().filter(|a| link_kind(a) == Some(0x101)) {
                if link
                    .get(LINKED_OBJECT_IDENTIFIER)
                    .and_then(|n| n.identifier_text().ok())
                    == Some(old.id.as_str())
                {
                    *link = object_link(0x101, &obj.id);
                    changed = true;
                }
            }
            if !changed {
                attributes::append(&mut key, object_link(0x101, &obj.id))?;
            }
            key.updated = at;
            self.store.put(&key)?;
        }
        self.unique_names(&obj, v)?;
        self.store.insert(&obj)?;
        tracing::info!(issuer=%issuer.id, certificate=%obj.id, replaced=%old.id, "certificate renewed");
        *placeholder = Some(obj.id.clone());
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
}
