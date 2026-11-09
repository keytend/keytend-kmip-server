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

//! Re-Provision (KMIP 2.0 section 6.1.44, 2.1 section 6.1.48, draft 3.0):
//! replacing the TLS client certificate of the connection that sends the
//! request. Offered only with `--provisioning-ca` (docs/re-provision.md).
//!
//! The certificate being replaced, `F`, is the connection's (`Channel`).
//! The three request forms:
//!
//! - **Certificate Request:** the provisioning CA issues a certificate for
//!   the request's public key. The subject and subjectAltName are copied
//!   from `F`, never from the request, so the CA re-issues the identity it
//!   is shown and never mints a new one.
//! - **Certificate:** the server adopts a certificate with `F`'s subject and
//!   subjectAltName, the clientAuth extended key usage and a new key, which
//!   the listener accepts.
//! - **No parameters:** the server generates a key pair like `F`'s, issues
//!   the certificate, and returns the private key's identifier. The private
//!   key exists only until the end of the message: the server never keeps a
//!   client's private key.
//!
//! Every form needs a key the principal has never used, and the new
//! certificate must pass the listener's own verification before anything
//! is written. The request and no-parameter forms must retrieve what they
//! create in the same message (`[Re-Provision, Get(ID Placeholder), ...]`):
//! the request is refused unless such a Get follows, and the message fails
//! as a whole unless that Get succeeded and, without parameters, a later
//! result named the certificate (`finish_message`). One Re-Provision runs
//! per message.
//!
//! The replacement takes effect when the message commits: hidden records
//! (records.rs) mark `F` Retired and the new certificate `N` Active, and new
//! connections presenting `F` are refused from then on (`main.rs`
//! `resolve_principal`). Open connections continue; a retired one can no
//! longer re-provision or obtain tickets (`channel_retired`).
use super::records::{PROVISIONING_OWNER, PROVISIONING_RECORD};
use super::*;
use crate::crypto::issuance;
use anyhow::Context;
use openssl::{
    nid::Nid,
    pkey::{Id, PKey, PKeyRef, Private, Public},
    x509::{X509, X509NameBuilder, X509NameRef, X509Ref},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// The listener's verification of a client certificate (leaf, untrusted
/// chain): the same trust anchors, CRLs, depth and profile checks as the
/// TLS handshake (`main.rs`).
type Verifier = Box<dyn Fn(&X509, &[X509]) -> Result<(), String> + Send + Sync>;

/// Records a principal may hold: Active ones and Retired ones whose
/// certificate has not expired. Expired ones are purged on each
/// Re-Provision.
const MAX_RECORDS_PER_PRINCIPAL: usize = 1024;
const GET: u32 = 10;
const GET_ATTRIBUTES: u32 = 11;
const RE_PROVISION: u32 = 53;
/// How far an issued certificate's notBefore is set back, so a verifier
/// whose clock trails this one (even by a second) accepts it at once.
const BACKDATE_SECONDS: i64 = 300;
/// Link Types (2.1 section 11.27).
const REPLACEMENT_OBJECT_LINK: u32 = 0x106;
const REPLACED_OBJECT_LINK: u32 = 0x107;
const PKCS12_CERTIFICATE_LINK: u32 = 0x10c;
/// Vendor Identification of the Message Extension that asks Re-Provision
/// for a validity period (docs/re-provision.md#validity-period).
pub(super) const EXTENSION_VENDOR: &str = "keytend_kmip_server";
/// Cryptographic Usage Mask bits: Sign, and Wrap Key (keyEncipherment).
const SIGN: u32 = 0x1;
const WRAP_KEY: u32 = 0x10;
/// The largest RSA key the server generates for the no-parameter form.
const MAX_GENERATED_RSA_BITS: u32 = 4096;
/// Certificate Request signature algorithms accepted: RSA PKCS#1 v1.5 and
/// ECDSA with SHA-224 to SHA-512 (no SHA-1 or MD5).
const REQUEST_SIGNATURES: [&[u8]; 8] = [
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04],
];
/// id-kp-clientAuth (1.3.6.1.5.5.7.3.2) and id-ce-extKeyUsage (2.5.29.37).
const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];

/// Re-Provision configuration: the provisioning CA and the listener's
/// certificate verifier (filled in with `--provisioning-ca`).
pub struct Provisioning {
    ca: X509,
    ca_key: PKey<Private>,
    ca_not_after: i64,
    verify: Verifier,
    /// Fingerprints that are already credentials: every policy entry and
    /// the server's own certificate. An adopted certificate is none of them.
    policy_fingerprints: HashSet<String>,
}

impl Provisioning {
    /// Load the provisioning CA certificate and key (PEM) and check them
    /// (docs/re-provision.md#provisioning-ca): the key matches, the
    /// certificate is a currently valid CA with keyCertSign, and the key
    /// file is not accessible to other users. In FIPS mode the key must
    /// also be approved for signing. `verify` is the listener's client
    /// verifier; `policy_fingerprints` are the fingerprints that are
    /// already credentials.
    pub fn load(
        ca: &std::path::Path,
        key: &std::path::Path,
        verify: Verifier,
        policy_fingerprints: HashSet<String>,
    ) -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(key)
                .with_context(|| format!("provisioning CA key {}", key.display()))?
                .permissions()
                .mode();
            anyhow::ensure!(
                mode & 0o007 == 0,
                "the provisioning CA key file must not be accessible to other users (mode {:03o}); use chmod o-rwx",
                mode & 0o777
            );
        }
        let certificates = X509::stack_from_pem(
            &std::fs::read(ca).with_context(|| format!("provisioning CA {}", ca.display()))?,
        )
        .context("the provisioning CA file is not PEM")?;
        let [ca] = <[X509; 1]>::try_from(certificates).map_err(|_| {
            anyhow::anyhow!("the provisioning CA file must hold exactly one certificate")
        })?;
        let pem = zeroize::Zeroizing::new(std::fs::read(key)?);
        let ca_key = PKey::private_key_from_pem(&pem)
            .context("the provisioning CA key file is not a PEM private key")?;
        anyhow::ensure!(
            matches!(ca_key.id(), Id::RSA | Id::EC),
            "the provisioning CA key must be RSA or EC"
        );
        let ca_not_after =
            issuance::check_issuer(&ca, &ca_key, now()).context("the provisioning CA")?;
        let constraints = crate::crypto::certificate_attributes::ca_constraints(&ca.to_der()?)?;
        anyhow::ensure!(
            constraints.key_cert_sign == Some(true),
            "the provisioning CA certificate lacks the keyCertSign key usage"
        );
        fips_policy::issuer_key(&ca_key).map_err(|f| {
            anyhow::anyhow!(
                "the provisioning CA key cannot sign in FIPS mode: {}",
                f.message
            )
        })?;
        if crate::fips::active() && ca_key.id() == Id::EC {
            let curve = ca_key.ec_key()?.group().curve_name();
            anyhow::ensure!(
                matches!(
                    curve,
                    Some(Nid::X9_62_PRIME256V1 | Nid::SECP384R1 | Nid::SECP521R1)
                ),
                "the provisioning CA key is on a curve FIPS mode does not approve"
            );
        }
        Ok(Self {
            ca,
            ca_key,
            ca_not_after,
            verify,
            policy_fingerprints,
        })
    }
    /// The provisioning CA certificate.
    pub fn certificate(&self) -> &X509 {
        &self.ca
    }
    /// Issue a client certificate for `key` in memory and run it through
    /// the listener's verifier. Startup refuses a provisioning CA whose
    /// certificates the listener would refuse (a Suite B profile, `--crl`
    /// without a CRL from this CA).
    pub fn self_test(&self, key: &PKeyRef<Private>) -> anyhow::Result<()> {
        let public = PKey::public_key_from_der(&key.public_key_to_der()?)?;
        let mut subject = X509NameBuilder::new()?;
        subject.append_entry_by_text("CN", "keytend-kmip-server provisioning self-test")?;
        let subject = subject.build();
        let der = self.issue(&subject, &[], &public, now(), None)?;
        let leaf = X509::from_der(&der)?;
        (self.verify)(&leaf, &[]).map_err(|reason| {
            anyhow::anyhow!(
                "a client certificate from the provisioning CA fails the listener's verification: {reason}"
            )
        })
    }
    /// An end-entity client certificate: CA false, digitalSignature (plus
    /// keyEncipherment for RSA), clientAuth, valid until `not_after` or else
    /// for a year or until the CA expires.
    fn issue(
        &self,
        subject: &X509NameRef,
        names: &[(u8, String)],
        public: &PKeyRef<Public>,
        at: i64,
        not_after: Option<i64>,
    ) -> anyhow::Result<Vec<u8>> {
        let usage = if public.id() == Id::RSA {
            SIGN | WRAP_KEY
        } else {
            SIGN
        };
        let not_before = at
            .saturating_sub(BACKDATE_SECONDS)
            .max(issuance::asn1_unix(self.ca.not_before())?);
        issuance::issue(&issuance::Issue {
            subject,
            alternative_names: names,
            public_key: public,
            issuer: &self.ca,
            issuer_key: &self.ca_key,
            issuer_not_after: self.ca_not_after,
            not_before,
            not_after: not_after.unwrap_or_else(|| {
                issuance::default_not_after(
                    not_before,
                    issuance::DEFAULT_VALIDITY_SECONDS,
                    self.ca_not_after,
                )
            }),
            usage,
            client_auth: true,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RecordState {
    Active,
    Retired,
}
/// What the store remembers about one client certificate fingerprint
/// (owner `PROVISIONING_OWNER`, identifier `fingerprint\0{hex}`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FingerprintRecord {
    fingerprint: String,
    state: RecordState,
    /// The certificate this one replaced (Active records).
    replaces: Option<String>,
    /// The certificate that replaced this one (Retired records).
    replaced_by: Option<String>,
    /// The policy entry that authorizes this certificate (the anchor).
    policy_fingerprint: String,
    principal: String,
    /// The Certificate object of a provisioned certificate.
    certificate: Option<String>,
    /// SHA-256 of the SubjectPublicKeyInfo: keys are never reused.
    spki_sha256: [u8; 32],
    /// The certificate's notAfter (Unix seconds).
    not_after: i64,
    created: i64,
    changed: i64,
}
/// What a Re-Provision message must deliver before it may commit
/// (`finish_message`).
pub(super) struct Delivery {
    /// The new certificate's fingerprint: its record exists only while the
    /// Re-Provision item is part of the message.
    fingerprint: String,
    /// The object a successful Get must return (the issued certificate, or
    /// the generated private key).
    get: String,
    /// An identifier a successful later result must name (the generated
    /// key's certificate, through its Link).
    disclose: Option<String>,
}
/// Whether any field of `n` is the identifier `id`.
/// Whether a Message Extension is this server's.
pub(super) fn ours(extension: &Node) -> bool {
    extension
        .get(VENDOR_IDENTIFICATION)
        .and_then(|n| n.string().ok())
        == Some(EXTENSION_VENDOR)
}
/// The notAfter a Re-Provision batch item asks for: this server's Message
/// Extension, whose Vendor Extension holds exactly one Deactivation Date.
/// The 2.1 and draft 3.0 payloads have no field for it.
fn requested_not_after(item: &Node) -> R<Option<i64>> {
    let mut found = None;
    for extension in item.all(MESSAGE_EXTENSION).filter(|e| ours(e)) {
        let invalid = || {
            fail(
                7,
                "The keytend_kmip_server Message Extension holds one Deactivation Date",
            )
        };
        if found.is_some() {
            return Err(invalid());
        }
        let fields = extension.required(VENDOR_EXTENSION)?.children()?;
        let [date] = fields else {
            return Err(invalid());
        };
        if date.tag != DEACTIVATION_DATE {
            return Err(invalid());
        }
        found = Some(date_value(date).map_err(|_| invalid())?);
    }
    Ok(found)
}
fn names(n: &Node, id: &str) -> bool {
    match &n.value {
        Value::Structure(fields) => fields.iter().any(|f| names(f, id)),
        _ => n.identifier_text().ok() == Some(id),
    }
}
fn record_id(fingerprint: &str) -> String {
    format!("fingerprint\0{fingerprint}")
}
fn fingerprint(der: &[u8]) -> String {
    hex::encode(openssl::sha::sha256(der))
}
fn spki_sha256<T: openssl::pkey::HasPublic>(key: &PKeyRef<T>) -> R<[u8; 32]> {
    Ok(openssl::sha::sha256(&key.public_key_to_der()?))
}
fn curve(key: &PKeyRef<Public>) -> Option<Nid> {
    key.ec_key().ok().and_then(|k| k.group().curve_name())
}
/// The same algorithm as the current key, and the same curve for EC.
fn same_kind(key: &PKeyRef<Public>, current: &PKeyRef<Public>) -> bool {
    key.id() == current.id() && (key.id() != Id::EC || curve(key) == curve(current))
}
/// One DER element: (tag, contents, rest).
fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |a, b| a << 8 | usize::from(*b));
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}
/// Whether a PKCS#10 request (DER) is signed with an accepted algorithm.
fn strong_request_signature(request: &[u8]) -> bool {
    (|| {
        let (0x30, body, _) = der(request)? else {
            return None;
        };
        let (0x30, _, rest) = der(body)? else {
            return None;
        };
        let (0x30, algorithm, _) = der(rest)? else {
            return None;
        };
        let (0x06, oid, _) = der(algorithm)? else {
            return None;
        };
        Some(REQUEST_SIGNATURES.contains(&oid))
    })()
    .unwrap_or(false)
}
/// Whether a certificate (DER) carries the clientAuth extended key usage.
fn client_auth(certificate: &[u8]) -> bool {
    (|| {
        let (0x30, body, _) = der(certificate)? else {
            return None;
        };
        let (0x30, mut tbs, _) = der(body)? else {
            return None;
        };
        while !tbs.is_empty() {
            let (tag, value, rest) = der(tbs)?;
            tbs = rest;
            if tag != 0xa3 {
                continue;
            }
            let (0x30, mut extensions, _) = der(value)? else {
                return None;
            };
            while !extensions.is_empty() {
                let (_, extension, rest) = der(extensions)?;
                extensions = rest;
                let (0x06, oid, mut fields) = der(extension)? else {
                    return None;
                };
                if oid != EXTENDED_KEY_USAGE {
                    continue;
                }
                let (mut tag, mut value, rest) = der(fields)?;
                if tag == 0x01 {
                    fields = rest;
                    (tag, value, _) = der(fields)?;
                }
                if tag != 0x04 {
                    return None;
                }
                let (0x30, mut purposes, _) = der(value)? else {
                    return None;
                };
                while !purposes.is_empty() {
                    let (tag, purpose, rest) = der(purposes)?;
                    purposes = rest;
                    if tag == 0x06 && purpose == CLIENT_AUTH {
                        return Some(true);
                    }
                }
                return Some(false);
            }
        }
        Some(false)
    })()
    .unwrap_or(false)
}
fn sorted_names(cert: &X509Ref) -> R<Vec<(u8, String)>> {
    let mut names = issuance::certificate_alternative_names(cert).map_err(|_| {
        fail(
            8,
            "The certificate's subject alternative names are not supported",
        )
    })?;
    names.sort();
    Ok(names)
}

/// The request form.
enum Form<'a> {
    Request(&'a Node),
    Certificate(&'a Node),
    Generate,
}
/// What one Re-Provision writes, computed before anything is written.
struct Replacement {
    certificate: Vec<u8>,
    /// Issued by the provisioning CA (request and no-parameter forms), or
    /// adopted.
    issued: bool,
    private_key: Option<PKey<Private>>,
}

impl Engine {
    /// Offer Re-Provision with this configuration.
    pub fn with_provisioning(mut self, provisioning: Provisioning) -> Self {
        self.provisioning = Some(provisioning);
        self
    }
    fn fingerprint_record(&self, fingerprint: &str) -> R<Option<FingerprintRecord>> {
        self.read_record(PROVISIONING_OWNER, &record_id(fingerprint))?
            .map(|material| {
                serde_json::from_slice(&material)
                    .context("unreadable provisioning record")
                    .map_err(Failure::from)
            })
            .transpose()
    }
    fn fingerprint_records(&self) -> R<Vec<FingerprintRecord>> {
        let mut records = self
            .list_records(PROVISIONING_OWNER)?
            .into_iter()
            .map(|(_, material)| {
                serde_json::from_slice::<FingerprintRecord>(&material)
                    .context("unreadable provisioning record")
                    .map_err(Failure::from)
            })
            .collect::<R<Vec<_>>>()?;
        records.sort_by(|a, b| (a.created, &a.fingerprint).cmp(&(b.created, &b.fingerprint)));
        Ok(records)
    }
    fn put_fingerprint_record(&mut self, record: &FingerprintRecord) -> R<()> {
        let material = serde_json::to_vec(record).map_err(anyhow::Error::from)?;
        self.write_record(
            PROVISIONING_OWNER,
            &record_id(&record.fingerprint),
            PROVISIONING_RECORD,
            material,
        )
    }
    /// What the store records about a client certificate fingerprint, for a
    /// new handshake (`main.rs` `resolve_principal`). An unreadable record
    /// is an error, so the connection is refused.
    pub fn provisioned_lookup(&self, fingerprint: &str) -> anyhow::Result<Lookup> {
        let record = self
            .fingerprint_record(fingerprint)
            .map_err(|f| anyhow::anyhow!("provisioning record: {}", f.message))?;
        Ok(match record {
            None => Lookup::Unknown,
            Some(r) if r.state == RecordState::Retired => Lookup::Retired,
            Some(r) => Lookup::Replacement {
                policy_fingerprint: r.policy_fingerprint,
                principal: r.principal,
            },
        })
    }
    /// The provisioning records for the startup log, and warnings about
    /// them against the policy (`policy`: fingerprint to principal name).
    /// The resolution follows `main.rs` `resolve_principal`.
    pub fn provisioning_records(
        &self,
        policy: &HashMap<String, String>,
    ) -> anyhow::Result<(Vec<String>, Vec<String>)> {
        let records = self
            .fingerprint_records()
            .map_err(|f| anyhow::anyhow!("provisioning records: {}", f.message))?;
        let mut lines = vec![];
        let mut warnings = vec![];
        let none = || "none".to_owned();
        for r in &records {
            let state = match r.state {
                RecordState::Active => "active",
                RecordState::Retired => "retired",
            };
            lines.push(format!(
                "provisioning record {}: {state}, principal {}, anchor {}, replaces {}, replaced by {}, certificate object {}, expires {}",
                r.fingerprint,
                r.principal,
                r.policy_fingerprint,
                r.replaces.clone().unwrap_or_else(none),
                r.replaced_by.clone().unwrap_or_else(none),
                r.certificate.clone().unwrap_or_else(none),
                crate::maintenance::rfc3339_utc(r.not_after),
            ));
            match r.state {
                RecordState::Retired if policy.contains_key(&r.fingerprint) => {
                    let anchored: Vec<_> = records
                        .iter()
                        .filter(|n| {
                            n.state == RecordState::Active && n.policy_fingerprint == r.fingerprint
                        })
                        .collect();
                    if anchored.is_empty() {
                        warnings.push(format!(
                            "{} was retired by a Re-Provision and is refused; remove it from the policy",
                            r.fingerprint
                        ));
                    }
                    for n in anchored {
                        warnings.push(format!(
                            "{} anchors active {}; add {} to the policy under the same name ({}) before removing {}",
                            r.fingerprint, n.fingerprint, n.fingerprint, n.principal, r.fingerprint
                        ));
                    }
                }
                RecordState::Retired => {}
                RecordState::Active => {
                    if let Some(name) = policy.get(&r.fingerprint)
                        && *name != r.principal
                    {
                        warnings.push(format!(
                            "{} is listed in the policy under {name} but was provisioned for {}: refused (conflict); list it under {} or remove it",
                            r.fingerprint, r.principal, r.principal
                        ));
                        continue;
                    }
                    match policy
                        .get(&r.policy_fingerprint)
                        .or_else(|| policy.get(&r.fingerprint))
                    {
                        None => warnings.push(format!(
                            "{} (provisioned for {}) is refused: its anchor {} is not in the policy; add it to the policy under {}",
                            r.fingerprint, r.principal, r.policy_fingerprint, r.principal
                        )),
                        Some(name) if *name != r.principal => warnings.push(format!(
                            "{} (provisioned for {}) is refused: its anchor {} is listed under {name}",
                            r.fingerprint, r.principal, r.policy_fingerprint
                        )),
                        Some(_) => {}
                    }
                }
            }
        }
        Ok((lines, warnings))
    }
    /// Whether the certificate of the request's connection has been retired
    /// by a Re-Provision. Such a connection stays open but cannot obtain new
    /// tickets or re-provision again.
    pub(super) fn channel_retired(&self) -> R<bool> {
        let Some(channel) = &self.channel else {
            return Ok(false);
        };
        Ok(self
            .fingerprint_record(&channel.fingerprint)?
            .is_some_and(|r| r.state == RecordState::Retired))
    }
    /// Re-Provision (2.1 section 6.1.48).
    pub(super) fn re_provision(
        &mut self,
        owner: &str,
        v: Version,
        item: &Node,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(p, &[CERTIFICATE_REQUEST, CERTIFICATE])?;
        let not_after = requested_not_after(item)?;
        // One attempt per message: a failed attempt (after generating and
        // signing) rolls back, and would otherwise let one message repeat
        // the work up to the batch limit.
        if std::mem::replace(&mut self.authorization.re_provision_attempted, true) {
            return Err(fail(12, "Only one Re-Provision may run in a message"));
        }
        // A ticket adds no power (the holder of the certificate can send
        // without one), and the replacement revokes the tickets the
        // certificate obtained, which would fail the retrieval.
        if self
            .authorization
            .identity
            .as_ref()
            .is_some_and(|i| i.is_ticket() || i.is_delegated())
        {
            return Err(fail(12, "Re-Provision is not accepted under a ticket"));
        }
        // The link credential is the certificate principal's.
        if system::certificate_principal(owner) != Some(owner) {
            return Err(fail(
                12,
                "Re-Provision acts for the certificate principal; send it without header credentials",
            ));
        }
        let Some(channel) = self.channel.clone() else {
            return Err(fail(
                12,
                "Re-Provision needs the TLS connection whose certificate it replaces",
            ));
        };
        if self.channel_retired()? {
            return Err(fail(
                12,
                "This connection's certificate has already been replaced",
            ));
        }
        let Some(provisioning) = self.provisioning.take() else {
            return Err(fail(5, "Re-Provision is not configured"));
        };
        let result =
            self.replace_certificate(&provisioning, owner, v, p, not_after, placeholder, &channel);
        self.provisioning = Some(provisioning);
        result
    }
    #[allow(clippy::too_many_arguments)]
    fn replace_certificate(
        &mut self,
        provisioning: &Provisioning,
        owner: &str,
        v: Version,
        p: &Node,
        not_after: Option<i64>,
        placeholder: &mut Option<String>,
        channel: &Channel,
    ) -> R<Vec<Node>> {
        let form = match (p.get(CERTIFICATE_REQUEST), p.get(CERTIFICATE)) {
            (Some(_), Some(_)) => {
                return Err(fail(
                    7,
                    "Give a Certificate Request or a Certificate, not both",
                ));
            }
            (Some(request), None) => Form::Request(request),
            (None, Some(certificate)) => Form::Certificate(certificate),
            (None, None) => Form::Generate,
        };
        if not_after.is_some() && matches!(form, Form::Certificate(_)) {
            return Err(fail(
                7,
                "A requested validity period applies only to a certificate the server issues",
            ));
        }
        // The retrieval the form needs: the operations must be
        // permitted, and the message must contain them.
        let needs: &[u32] = match form {
            Form::Request(_) => &[GET],
            Form::Generate => &[GET, GET_ATTRIBUTES],
            Form::Certificate(_) => &[],
        };
        if let Some(allowed) = &self.authorization.allowed
            && needs.iter().any(|op| !allowed.contains(op))
        {
            return Err(fail(
                12,
                "Re-Provision needs Get (and, without parameters, Get Attributes) in the certificate policy",
            ));
        }
        // The current certificate must still pass the listener: unexpired
        // and not revoked by the CRL (6.1.48 "SHALL fail if ... Revoked").
        let current =
            X509::from_der(&channel.certificate).map_err(|_| fail(12, "Unreadable certificate"))?;
        let chain = channel
            .chain
            .iter()
            .map(|der| X509::from_der(der))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| fail(12, "Unreadable certificate chain"))?;
        if let Err(reason) = (provisioning.verify)(&current, &chain) {
            tracing::warn!(principal = %owner, fingerprint = %channel.fingerprint, %reason, "Re-Provision refused: the current certificate fails verification");
            return Err(fail(
                12,
                "The current client certificate no longer passes verification",
            ));
        }
        if needs
            .iter()
            .any(|op| !self.authorization.later_placeholder_ops.contains(op))
        {
            return Err(fail(
                7,
                "Re-Provision must be followed in the same message by a Get of the ID Placeholder (and, without parameters, a Get Attributes of it)",
            ));
        }
        let current_key = current.public_key()?;
        let current_spki = spki_sha256(&current_key)?;
        let at = now();
        // A requested notAfter: Invalid Field when it has passed or is past
        // the provisioning CA's notAfter, never cut short.
        if let Some(not_after) = not_after {
            if not_after <= at {
                return Err(fail(7, "The requested Deactivation Date has passed"));
            }
            if not_after > provisioning.ca_not_after {
                return Err(fail(
                    7,
                    "The requested validity ends after the provisioning CA's notAfter",
                ));
            }
        }
        // Records whose certificate expired are dropped; the rest bound the
        // keys this principal may not use again.
        let mut records = vec![];
        for record in self.fingerprint_records()? {
            if record.not_after <= at {
                self.remove_record(PROVISIONING_OWNER, &record_id(&record.fingerprint))?;
            } else {
                records.push(record);
            }
        }
        let mut used: HashSet<[u8; 32]> = records
            .iter()
            .filter(|r| r.principal == owner)
            .map(|r| r.spki_sha256)
            .collect();
        used.insert(current_spki);
        let subject = current.subject_name();
        let names = sorted_names(&current)?;
        let replacement = match form {
            Form::Request(node) => {
                let (kind, bytes) = certificate_request::read(node)?;
                let request = issuance::parse_request(kind, &bytes)
                    .map_err(|_| fail(7, "Invalid Certificate Request"))?;
                if !strong_request_signature(&request.to_der()?) {
                    return Err(fail(
                        7,
                        "The Certificate Request must be signed with SHA-224 or stronger (RSA PKCS#1 v1.5 or ECDSA)",
                    ));
                }
                let public = request
                    .public_key()
                    .map_err(|_| fail(7, "Invalid Certificate Request key"))?;
                if !issuance::supported_subject_key(&public) || !same_kind(&public, &current_key) {
                    return Err(fail(
                        7,
                        "The new key must be of the current certificate's algorithm (and curve): RSA-2048 or more, or EC P-256, P-384 or P-521",
                    ));
                }
                if used.contains(&spki_sha256(&public)?) {
                    return Err(fail(7, "Re-Provision needs a key never used before"));
                }
                Replacement {
                    certificate: self.issue_replacement(
                        provisioning,
                        subject,
                        &names,
                        &public,
                        at,
                        not_after,
                    )?,
                    issued: true,
                    private_key: None,
                }
            }
            Form::Generate => {
                let key = match current_key.id() {
                    Id::RSA => {
                        let bits = current_key.bits().max(2048);
                        if bits > MAX_GENERATED_RSA_BITS {
                            return Err(fail(
                                8,
                                "Generated RSA keys are at most 4096 bits; send a Certificate Request",
                            ));
                        }
                        crypto::rsa::generate(bits)
                    }
                    Id::EC => match curve(&current_key) {
                        Some(Nid::X9_62_PRIME256V1) => crypto::ec::generate(7),
                        Some(Nid::SECP384R1) => crypto::ec::generate(10),
                        Some(Nid::SECP521R1) => crypto::ec::generate(13),
                        _ => {
                            return Err(fail(
                                8,
                                "Keys are generated on P-256, P-384 and P-521 only; send a Certificate Request",
                            ));
                        }
                    },
                    _ => {
                        return Err(fail(
                            8,
                            "Keys are generated for RSA and EC certificates only",
                        ));
                    }
                }
                .map_err(|_| fail(10, "Key generation failed"))?;
                let public = PKey::public_key_from_der(&key.public_key_to_der()?)?;
                if used.contains(&spki_sha256(&public)?) {
                    return Err(fail(10, "Key generation repeated a key"));
                }
                Replacement {
                    certificate: self.issue_replacement(
                        provisioning,
                        subject,
                        &names,
                        &public,
                        at,
                        not_after,
                    )?,
                    issued: true,
                    private_key: Some(key),
                }
            }
            Form::Certificate(node) => {
                if certificate::read_type(node)? != 1 {
                    return Err(fail(8, "Only X.509 certificates can be adopted"));
                }
                let bytes = node.required(CERTIFICATE_VALUE)?.byte_string()?;
                let adopted = X509::from_der(bytes)
                    .ok()
                    .filter(|c| c.to_der().ok().as_deref() == Some(bytes))
                    .ok_or(fail(7, "Invalid certificate"))?;
                self.check_adopted(provisioning, &adopted, bytes, &current, &chain, &used)?;
                Replacement {
                    certificate: bytes.to_vec(),
                    issued: false,
                    private_key: None,
                }
            }
        };
        let new = X509::from_der(&replacement.certificate)?;
        let new_fingerprint = fingerprint(&replacement.certificate);
        let new_records =
            1 + usize::from(!records.iter().any(|r| r.fingerprint == channel.fingerprint));
        if records.iter().filter(|r| r.principal == owner).count() + new_records
            > MAX_RECORDS_PER_PRINCIPAL
        {
            return Err(server_limit(
                v,
                "Too many provisioning records for this principal",
            ));
        }
        // Everything is checked: write the objects and the records. All of
        // it commits with the message, or none of it.
        let previous = records
            .iter()
            .find(|r| r.fingerprint == channel.fingerprint)
            .cloned();
        let certificate_id =
            self.store_certificate(owner, v, &replacement, previous.as_ref(), at, not_after)?;
        let returned = match &replacement.private_key {
            Some(key) => self.store_private_key(owner, v, key, &certificate_id, at)?,
            None => certificate_id.clone(),
        };
        let mut retired = previous.unwrap_or_else(|| FingerprintRecord {
            fingerprint: channel.fingerprint.clone(),
            state: RecordState::Active,
            replaces: None,
            replaced_by: None,
            policy_fingerprint: channel.policy_fingerprint.clone(),
            principal: owner.to_owned(),
            certificate: None,
            spki_sha256: current_spki,
            not_after: issuance::asn1_unix(current.not_after()).unwrap_or(at),
            created: at,
            changed: at,
        });
        retired.state = RecordState::Retired;
        retired.replaced_by = Some(new_fingerprint.clone());
        retired.changed = at;
        self.put_fingerprint_record(&retired)?;
        self.put_fingerprint_record(&FingerprintRecord {
            fingerprint: new_fingerprint.clone(),
            state: RecordState::Active,
            replaces: Some(channel.fingerprint.clone()),
            replaced_by: None,
            policy_fingerprint: channel.policy_fingerprint.clone(),
            principal: owner.to_owned(),
            certificate: Some(certificate_id.clone()),
            spki_sha256: spki_sha256(&*new.public_key()?)?,
            not_after: issuance::asn1_unix(new.not_after())?,
            created: at,
            changed: at,
        })?;
        self.tickets.revoke_fingerprint(&channel.fingerprint);
        // The same message must deliver what only the client may hold: the
        // generated key and its certificate's identifier, or the issued
        // certificate.
        if replacement.private_key.is_some() {
            self.authorization
                .message_scoped
                .push((owner.to_owned(), returned.clone()));
            self.authorization.must_deliver.push(Delivery {
                fingerprint: new_fingerprint.clone(),
                get: returned.clone(),
                disclose: Some(certificate_id.clone()),
            });
        } else if replacement.issued {
            self.authorization.must_deliver.push(Delivery {
                fingerprint: new_fingerprint.clone(),
                get: returned.clone(),
                disclose: None,
            });
        }
        tracing::warn!(
            principal = %owner,
            old = %channel.fingerprint,
            new = %new_fingerprint,
            certificate = %certificate_id,
            "Re-Provision: the client certificate is replaced when this message commits"
        );
        *placeholder = Some(returned.clone());
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, returned)])
    }
    /// Issue `N` and check it as the listener would, before any record.
    fn issue_replacement(
        &self,
        provisioning: &Provisioning,
        subject: &X509NameRef,
        names: &[(u8, String)],
        public: &PKeyRef<Public>,
        at: i64,
        not_after: Option<i64>,
    ) -> R<Vec<u8>> {
        let der = provisioning
            .issue(subject, names, public, at, not_after)
            .map_err(|e| {
                tracing::warn!(error = %e, "Re-Provision issuance failed");
                fail(10, "Certificate issuance failed")
            })?;
        let issued = X509::from_der(&der)?;
        if let Err(reason) = (provisioning.verify)(&issued, &[]) {
            tracing::warn!(%reason, "Re-Provision refused: the issued certificate fails the listener's verification");
            return Err(fail(
                10,
                "The issued certificate would not be accepted by the listener",
            ));
        }
        Ok(der)
    }
    /// The certificate form: a new client certificate of the same
    /// identity that the listener accepts. Invalid Field otherwise.
    fn check_adopted(
        &self,
        provisioning: &Provisioning,
        adopted: &X509,
        der: &[u8],
        current: &X509,
        chain: &[X509],
        used: &HashSet<[u8; 32]>,
    ) -> R<()> {
        let refuse = |message| Err(fail(7, message));
        let constraints = crate::crypto::certificate_attributes::ca_constraints(der)
            .map_err(|_| fail(7, "Invalid certificate"))?;
        if constraints.ca {
            return refuse("A CA certificate cannot be a client credential");
        }
        if !client_auth(der) {
            return refuse("The certificate lacks the clientAuth extended key usage");
        }
        let fp = fingerprint(der);
        if provisioning.policy_fingerprints.contains(&fp) || self.fingerprint_record(&fp)?.is_some()
        {
            return refuse("The certificate is already a credential");
        }
        if adopted.subject_name().to_der()? != current.subject_name().to_der()?
            || sorted_names(adopted)? != sorted_names(current)?
        {
            return refuse(
                "The certificate's subject and alternative names must be the current certificate's",
            );
        }
        let key = adopted.public_key()?;
        if !same_kind(&key, &*current.public_key()?) {
            return refuse(
                "The certificate's key must be of the current certificate's algorithm and curve",
            );
        }
        if used.contains(&spki_sha256(&key)?) {
            return refuse("Re-Provision needs a key never used before");
        }
        if let Err(reason) = (provisioning.verify)(adopted, chain) {
            tracing::warn!(%reason, "Re-Provision refused: the adopted certificate fails the listener's verification");
            return refuse("The certificate would not be accepted by the listener");
        }
        Ok(())
    }
    /// Store `N` as a Certificate object of the principal. When the replaced
    /// certificate was provisioned too, the two objects are linked.
    fn store_certificate(
        &mut self,
        owner: &str,
        v: Version,
        replacement: &Replacement,
        previous: Option<&FingerprintRecord>,
        at: i64,
        not_after: Option<i64>,
    ) -> R<String> {
        let mut dates = vec![Node::date(ACTIVATION_DATE, at)];
        // A requested notAfter is also the certificate's Deactivation Date.
        dates.extend(not_after.map(|d| Node::date(DEACTIVATION_DATE, d)));
        let payload = Node::structure(
            REQUEST_PAYLOAD,
            vec![
                Node::enumeration(OBJECT_TYPE, 1),
                Node::structure(
                    CERTIFICATE,
                    vec![
                        Node::enumeration(CERTIFICATE_TYPE, 1),
                        Node::bytes(CERTIFICATE_VALUE, replacement.certificate.clone()),
                    ],
                ),
                Node::structure(ATTRIBUTES, dates),
            ],
        );
        let mut obj = self.build_object(owner, v, &payload, true)?;
        if replacement.issued {
            metadata::initialize(&mut obj, v, true)?;
        }
        obj.metadata.fresh = Some(true);
        let replaced = previous
            .and_then(|r| r.certificate.as_deref())
            .map(|id| self.store.get(owner, id))
            .transpose()?
            .flatten();
        if let Some(mut old) = replaced {
            attributes::append(&mut obj, object_link(REPLACED_OBJECT_LINK, &old.id))?;
            attributes::append(&mut old, object_link(REPLACEMENT_OBJECT_LINK, &obj.id))?;
            old.updated = at;
            self.store.put(&old)?;
        }
        self.store.insert(&obj)?;
        Ok(obj.id.clone())
    }
    /// The generated private key, for this message only: Sensitive False,
    /// Extractable True, and a PKCS#12 Certificate Link to `N` (no public
    /// key object is kept).
    fn store_private_key(
        &mut self,
        owner: &str,
        v: Version,
        key: &PKey<Private>,
        certificate: &str,
        at: i64,
    ) -> R<String> {
        let (algorithm, format, material, bits) = if key.id() == Id::RSA {
            (4, 3, key.rsa()?.private_key_to_der()?, key.bits())
        } else {
            let format = ec::default_format(4, 26, v);
            let material = if format == 6 {
                key.ec_key()?.private_key_to_der()?
            } else {
                key.private_key_to_pkcs8()?
            };
            (26, format, material, key.bits())
        };
        let mut obj = Object {
            id: crypto::uuid(),
            owner: owner.to_owned(),
            object_type: 4,
            certificate_type: 1,
            opaque_type: opaque::LEGACY_TYPE,
            pgp_version: pgp::DEFAULT_VERSION,
            secret_type: 2,
            format,
            algorithm,
            bits,
            usage: SIGN,
            protection_mask: protection::SOFTWARE,
            usage_consumed: false,
            replacement_id: None,
            wrapped: None,
            imported: false,
            metadata: Default::default(),
            split: None,
            state: 1,
            material,
            attrs: vec![
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, SIGN as i32),
                Node::boolean(SENSITIVE, false),
                Node::boolean(EXTRACTABLE, true),
                Node::date(ACTIVATION_DATE, at),
                object_link(PKCS12_CERTIFICATE_LINK, certificate),
            ],
            attribute_indices: Default::default(),
            created: at,
            updated: at,
        };
        metadata::initialize(&mut obj, v, true)?;
        obj.metadata.fresh = Some(true);
        usage::initialize(&mut obj, self.maximum_lease)?;
        add_digest(&mut obj)?;
        attributes::limits(&obj.attrs)?;
        apply_dates(&mut obj);
        self.store.insert(&obj)?;
        Ok(obj.id.clone())
    }
    /// Items after a Re-Provision in its message may only read: Get, Get
    /// Attributes and Get Attribute List. Anything else could remove or
    /// change what the client still has to fetch (the no-parameter form's
    /// certificate, fetched in a later message) after the commit guard saw
    /// it delivered.
    pub(super) fn after_re_provision(&self, op: u32) -> R<()> {
        if self.authorization.re_provision_attempted && ![GET, GET_ATTRIBUTES, 12].contains(&op) {
            return Err(fail(
                12,
                "Only Get, Get Attributes and Get Attribute List may follow a Re-Provision in its message",
            ));
        }
        Ok(())
    }
    /// The last step of a message, before it commits (and before
    /// server-to-client messages are derived from its changes).
    ///
    /// 1. The commit guard: for each Re-Provision that is still part of the
    ///    message (its new fingerprint record exists; a rolled-back item
    ///    removed it), the message's results must include a successful Get
    ///    of the object the client had to fetch, and, for the no-parameter
    ///    form, a successful result that names the certificate. Otherwise
    ///    the whole message fails and nothing commits, so a client never
    ///    loses its credential to a retrieval that failed, was answered
    ///    without the identifier, or found the object removed.
    /// 2. Removes the message-scoped objects that still exist.
    ///
    /// An error fails the whole message.
    pub(super) fn finish_message(&mut self, responses: &[Node]) -> R<()> {
        for delivery in std::mem::take(&mut self.authorization.must_deliver) {
            if self
                .read_record(PROVISIONING_OWNER, &record_id(&delivery.fingerprint))?
                .is_none()
            {
                continue;
            }
            let succeeded =
                |item: &&Node| item.get(RESULT_STATUS).and_then(|n| n.number().ok()) == Some(0);
            let fetched = responses.iter().filter(succeeded).any(|item| {
                item.get(OPERATION).and_then(|n| n.number().ok()) == Some(GET)
                    && item
                        .get(RESPONSE_PAYLOAD)
                        .and_then(|p| p.get(UNIQUE_IDENTIFIER))
                        .and_then(|n| n.identifier_text().ok())
                        == Some(delivery.get.as_str())
            });
            let disclosed = delivery.disclose.as_ref().is_none_or(|id| {
                responses.iter().filter(succeeded).any(|item| {
                    item.get(OPERATION).and_then(|n| n.number().ok()) != Some(RE_PROVISION)
                        && item.get(RESPONSE_PAYLOAD).is_some_and(|p| names(p, id))
                })
            });
            if !fetched || !disclosed {
                return Err(fail(
                    7,
                    "The new credential was not retrieved in the Re-Provision message; nothing was changed",
                ));
            }
        }
        for (owner, id) in std::mem::take(&mut self.authorization.message_scoped) {
            if self.store.get(&owner, &id)?.is_some() {
                self.store.remove(&owner, &id)?;
                self.streams.invalidate_key(&owner, &id);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(dir: &std::path::Path) -> Engine {
        let master = dir.join("master");
        std::fs::write(&master, [7; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Engine::new(Store::open(&dir.join("s.sqlite"), &master).unwrap(), false)
    }

    fn record(
        fingerprint: &str,
        principal: &str,
        state: RecordState,
        not_after: i64,
    ) -> FingerprintRecord {
        FingerprintRecord {
            fingerprint: fingerprint.to_owned(),
            state,
            replaces: None,
            replaced_by: None,
            policy_fingerprint: "a".repeat(64),
            principal: principal.to_owned(),
            certificate: None,
            spki_sha256: openssl::sha::sha256(fingerprint.as_bytes()),
            not_after,
            created: 1,
            changed: 1,
        }
    }

    #[test]
    fn finish_message_removes_scoped_objects_and_skips_missing_ones() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(dir.path());
        engine
            .write_record("\0test", "kept\0a", 0x8000_00ff, b"x".to_vec())
            .unwrap();
        engine.authorization.message_scoped = vec![
            ("\0test".into(), "kept\0a".into()),
            ("\0test".into(), "gone\0b".into()),
        ];
        engine.finish_message(&[]).unwrap();
        assert!(engine.read_record("\0test", "kept\0a").unwrap().is_none());
        assert!(engine.authorization.message_scoped.is_empty());
        // Nothing left to do: a second call is a no-op.
        engine.finish_message(&[]).unwrap();
    }

    #[test]
    fn the_commit_guard_needs_a_get_and_the_disclosed_identifier() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(dir.path());
        let item = |op: u32, status: u32, payload: Vec<Node>| {
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, op),
                    Node::enumeration(RESULT_STATUS, status),
                    Node::structure(RESPONSE_PAYLOAD, payload),
                ],
            )
        };
        let delivery = || Delivery {
            fingerprint: "n".repeat(64),
            get: "key".into(),
            disclose: Some("cert".into()),
        };
        // The Re-Provision rolled back (no record): nothing to check.
        engine.authorization.must_deliver = vec![delivery()];
        engine.finish_message(&[]).unwrap();
        engine
            .write_record(
                PROVISIONING_OWNER,
                &record_id(&"n".repeat(64)),
                PROVISIONING_RECORD,
                b"{}".to_vec(),
            )
            .unwrap();
        let got = item(GET, 0, vec![Node::text(UNIQUE_IDENTIFIER, "key")]);
        let link = item(11, 0, vec![Node::text(LINKED_OBJECT_IDENTIFIER, "cert")]);
        for (case, (responses, ok)) in [
            (vec![], false),
            (vec![got.clone()], false),
            (vec![link.clone()], false),
            (
                vec![
                    item(GET, 1, vec![Node::text(UNIQUE_IDENTIFIER, "key")]),
                    link.clone(),
                ],
                false,
            ),
            (
                vec![
                    got.clone(),
                    item(11, 1, vec![Node::text(LINKED_OBJECT_IDENTIFIER, "cert")]),
                ],
                false,
            ),
            (vec![got.clone(), link.clone()], true),
        ]
        .into_iter()
        .enumerate()
        {
            engine.authorization.must_deliver = vec![delivery()];
            assert_eq!(engine.finish_message(&responses).is_ok(), ok, "case {case}");
        }
    }

    #[test]
    fn message_lists_never_outlive_a_message() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(dir.path());
        engine.authorization.message_scoped = vec![("\0test".into(), "stale".into())];
        engine.authorization.must_deliver = vec![Delivery {
            fingerprint: "stale".into(),
            get: "stale".into(),
            disclose: None,
        }];
        // A message that fails before any item runs.
        let malformed = Node::structure(REQUEST_MESSAGE, vec![]);
        engine.process("alice", &malformed).unwrap();
        assert!(engine.authorization.message_scoped.is_empty());
        assert!(engine.authorization.must_deliver.is_empty());
        assert!(engine.authorization.later_placeholder_ops.is_empty());
    }

    #[test]
    fn with_channel_sets_the_connection_for_one_call_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(dir.path());
        let channel = Channel {
            fingerprint: "f".repeat(64),
            policy_fingerprint: "f".repeat(64),
            certificate: vec![],
            chain: vec![],
        };
        let seen = engine.with_channel(&channel, |e| {
            e.channel.as_ref().map(|c| c.fingerprint.clone())
        });
        assert_eq!(seen, Some(channel.fingerprint.clone()));
        assert!(engine.channel.is_none());
        assert_eq!(
            engine.provisioned_lookup(&channel.fingerprint).unwrap(),
            Lookup::Unknown
        );
    }

    #[test]
    fn channel_retired_reads_the_record_of_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(dir.path());
        let (retired, active) = ("b".repeat(64), "c".repeat(64));
        engine
            .put_fingerprint_record(&record(&retired, "alice", RecordState::Retired, i64::MAX))
            .unwrap();
        engine
            .put_fingerprint_record(&record(&active, "alice", RecordState::Active, i64::MAX))
            .unwrap();
        assert!(!engine.channel_retired().unwrap());
        for (fingerprint, expected) in
            [(&retired, true), (&active, false), (&"d".repeat(64), false)]
        {
            let channel = Channel {
                fingerprint: fingerprint.clone(),
                policy_fingerprint: fingerprint.clone(),
                certificate: vec![],
                chain: vec![],
            };
            assert_eq!(
                engine.with_channel(&channel, |e| e.channel_retired().unwrap()),
                expected
            );
        }
        assert_eq!(
            engine.provisioned_lookup(&retired).unwrap(),
            Lookup::Retired
        );
        assert_eq!(
            engine.provisioned_lookup(&active).unwrap(),
            Lookup::Replacement {
                policy_fingerprint: "a".repeat(64),
                principal: "alice".into()
            }
        );
        // A record that does not decode fails closed.
        engine
            .write_record(
                PROVISIONING_OWNER,
                &record_id(&"e".repeat(64)),
                PROVISIONING_RECORD,
                b"{}".to_vec(),
            )
            .unwrap();
        assert!(engine.provisioned_lookup(&"e".repeat(64)).is_err());
    }

    #[test]
    fn request_signatures_and_client_auth_are_read_from_the_der() {
        use openssl::{
            hash::MessageDigest,
            x509::{X509ReqBuilder, extension::ExtendedKeyUsage},
        };
        let key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        for (digest, strong) in [
            (MessageDigest::sha1(), false),
            (MessageDigest::md5(), false),
            (MessageDigest::sha256(), true),
            (MessageDigest::sha512(), true),
        ] {
            let mut b = X509ReqBuilder::new().unwrap();
            b.set_pubkey(&key).unwrap();
            if b.sign(&key, digest).is_err() {
                continue;
            }
            assert_eq!(
                strong_request_signature(&b.build().to_der().unwrap()),
                strong
            );
        }
        assert!(!strong_request_signature(&[0x30, 0x80]));
        for (usage, expected) in [
            (
                Some(ExtendedKeyUsage::new().client_auth().build().unwrap()),
                true,
            ),
            (
                Some(ExtendedKeyUsage::new().server_auth().build().unwrap()),
                false,
            ),
            (
                Some(
                    ExtendedKeyUsage::new()
                        .critical()
                        .server_auth()
                        .client_auth()
                        .build()
                        .unwrap(),
                ),
                true,
            ),
            (None, false),
        ] {
            let mut b = X509::builder().unwrap();
            b.set_version(2).unwrap();
            b.set_pubkey(&key).unwrap();
            b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
                .unwrap();
            if let Some(usage) = usage {
                b.append_extension(usage).unwrap();
            }
            b.sign(&key, MessageDigest::sha256()).unwrap();
            assert_eq!(client_auth(&b.build().to_der().unwrap()), expected);
        }
    }

    #[test]
    fn startup_listing_flags_records_of_one_principal_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(dir.path());
        let anchor = "a".repeat(64);
        engine
            .put_fingerprint_record(&record(&"b".repeat(64), "alice", RecordState::Active, 5))
            .unwrap();
        let policy = HashMap::from([(anchor.clone(), "alice".to_owned())]);
        let (lines, warnings) = engine.provisioning_records(&policy).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("active, principal alice"), "{lines:?}");
        assert!(warnings.is_empty(), "{warnings:?}");
        let policy = HashMap::from([(anchor, "bob".to_owned())]);
        let (_, warnings) = engine.provisioning_records(&policy).unwrap();
        assert!(warnings[0].contains("listed under bob"), "{warnings:?}");
    }

    #[test]
    fn backdating_never_goes_before_the_provisioning_ca() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, ca_key, client, _) = pki();
        let ca_path = dir.path().join("ca.pem");
        let key_path = dir.path().join("ca.key");
        std::fs::write(&ca_path, ca.to_pem().unwrap()).unwrap();
        std::fs::write(&key_path, ca_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let provisioning = Provisioning::load(
            &ca_path,
            &key_path,
            Box::new(|_: &X509, _: &[X509]| Ok(())),
            HashSet::new(),
        )
        .unwrap();
        let ca_start = issuance::asn1_unix(ca.not_before()).unwrap();
        let public = client.public_key().unwrap();
        let issue = |at: i64| {
            let der = provisioning
                .issue(client.subject_name(), &[], &public, at, None)
                .unwrap();
            issuance::asn1_unix(X509::from_der(&der).unwrap().not_before()).unwrap()
        };
        // The CA was issued just now: the floor is its own notBefore.
        assert_eq!(issue(ca_start + 10), ca_start);
        // Later on, the full five minutes.
        assert_eq!(issue(ca_start + 3600), ca_start + 3600 - BACKDATE_SECONDS);
    }

    /// A synthetic CA and client certificate, for the record cap.
    fn pki() -> (X509, PKey<Private>, X509, PKey<Private>) {
        use openssl::{
            asn1::Asn1Time,
            hash::MessageDigest,
            x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
        };
        let ec = |nid| {
            PKey::from_ec_key(
                openssl::ec::EcKey::generate(&openssl::ec::EcGroup::from_curve_name(nid).unwrap())
                    .unwrap(),
            )
            .unwrap()
        };
        let name = |cn: &str| {
            let mut n = X509NameBuilder::new().unwrap();
            n.append_entry_by_text("CN", cn).unwrap();
            n.build()
        };
        let ca_key = ec(Nid::X9_62_PRIME256V1);
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name("ca")).unwrap();
        b.set_issuer_name(&name("ca")).unwrap();
        b.set_pubkey(&ca_key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(KeyUsage::new().key_cert_sign().build().unwrap())
            .unwrap();
        b.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca = b.build();
        let key = ec(Nid::X9_62_PRIME256V1);
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name("client")).unwrap();
        b.set_issuer_name(&name("ca")).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(10).unwrap())
            .unwrap();
        b.append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
            .unwrap();
        b.sign(&ca_key, MessageDigest::sha256()).unwrap();
        (ca, ca_key, b.build(), key)
    }

    #[test]
    fn the_record_cap_is_per_principal_and_expired_records_are_purged() {
        use openssl::{hash::MessageDigest, x509::X509ReqBuilder};
        let dir = tempfile::tempdir().unwrap();
        let (ca, ca_key, client, client_key) = pki();
        let ca_path = dir.path().join("ca.pem");
        let key_path = dir.path().join("ca.key");
        std::fs::write(&ca_path, ca.to_pem().unwrap()).unwrap();
        std::fs::write(&key_path, ca_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o604)).unwrap();
            let error = Provisioning::load(
                &ca_path,
                &key_path,
                Box::new(|_: &X509, _: &[X509]| Ok(())),
                HashSet::new(),
            )
            .err()
            .unwrap();
            assert!(error.to_string().contains("other users"), "{error}");
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let provisioning = Provisioning::load(
            &ca_path,
            &key_path,
            Box::new(|_: &X509, _: &[X509]| Ok(())),
            HashSet::new(),
        )
        .unwrap();
        let mut engine = engine(dir.path()).with_provisioning(provisioning);
        let fp = fingerprint(&client.to_der().unwrap());
        let channel = Channel {
            fingerprint: fp.clone(),
            policy_fingerprint: fp,
            certificate: client.to_der().unwrap(),
            chain: vec![],
        };
        let far = now() + 86_400;
        // 1,023 live records for alice (F and N make 1,025), plenty for bob,
        // and expired ones that are purged.
        for i in 0..1023 {
            let id = format!("{i:064x}");
            engine
                .put_fingerprint_record(&record(&id, "alice", RecordState::Retired, far))
                .unwrap();
        }
        for i in 0..1100 {
            let id = format!("b{i:063x}");
            engine
                .put_fingerprint_record(&record(&id, "bob", RecordState::Retired, far))
                .unwrap();
        }
        let request = || {
            let key = PKey::from_ec_key(
                openssl::ec::EcKey::generate(
                    &openssl::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            let mut b = X509ReqBuilder::new().unwrap();
            b.set_pubkey(&key).unwrap();
            b.sign(&key, MessageDigest::sha256()).unwrap();
            Node::structure(
                REQUEST_PAYLOAD,
                vec![Node::structure(
                    CERTIFICATE_REQUEST,
                    vec![
                        Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                        Node::bytes(CERTIFICATE_REQUEST_VALUE, b.build().to_der().unwrap()),
                    ],
                )],
            )
        };
        let mut placeholder = None;
        let run = |engine: &mut Engine, p: &Node, placeholder: &mut Option<String>| {
            // Each call stands for its own message.
            engine.authorization.later_placeholder_ops = vec![GET];
            engine.authorization.re_provision_attempted = false;
            engine.with_channel(&channel, |e| {
                e.re_provision("alice", Version(2, 1), p, p, placeholder)
            })
        };
        let refused = run(&mut engine, &request(), &mut placeholder)
            .err()
            .unwrap();
        assert_eq!(refused.reason, 0x3a);
        // Expire one of alice's: there is room again.
        engine
            .put_fingerprint_record(&record(
                &format!("{:064x}", 0),
                "alice",
                RecordState::Retired,
                5,
            ))
            .unwrap();
        engine
            .put_fingerprint_record(&record(
                &format!("{:064x}", 1),
                "alice",
                RecordState::Retired,
                5,
            ))
            .unwrap();
        assert!(run(&mut engine, &request(), &mut placeholder).is_ok());
        assert!(
            engine
                .fingerprint_record(&format!("{:064x}", 0))
                .unwrap()
                .is_none()
        );
        drop(client_key);
    }
}
