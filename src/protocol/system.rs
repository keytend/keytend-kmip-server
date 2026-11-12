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

//! Draft 3.0 (CSD02) System Objects, request-header credentials and
//! Obliterate (Set/Get Constraints are in constraints.rs; Login, Logout,
//! Delegated Login and the ticket store are in tickets.rs).
//!
//! Identity model. Mutual TLS stays mandatory and selects the certificate
//! principal, which owns every object. Profiles section 3.1.3 (1.1 through
//! 3.0) lets a server combine request credentials with the channel identity,
//! so a Username and Password, Device or Ticket credential authenticates a
//! user or device of that principal only; see `Engine::authenticate`, which
//! serves every protocol version. Users and credentials of one principal are never
//! visible to another. Creating or obliterating System Objects requires a
//! verified administrator: a users-file user marked `administrator` (spec
//! section 2.1: special authentication SHOULD be enforced for System Objects).
//!
//! A username has one source. Users-file users and System Users never share a
//! name: creation refuses a users-file name and startup refuses a users file
//! naming an existing or obliterated System User. An obliterated User leaves a
//! hidden retired-name record, so its name, which keys the credential identity
//! that owns objects, is never issued again. Tickets are re-checked
//! against their user, device and credential on every use and are revoked
//! when either is obliterated.
//!
//! System Objects are stored in the same encrypted, authenticated store under
//! a per-principal namespace that no configured principal can name (policy
//! names exclude NUL). Generic managed-object operations therefore never reach
//! them, and earlier protocol versions cannot observe them.
use super::system_credentials::{
    DEVICE_CREDENTIAL_OBJECT, HASHED_PASSWORD_CREDENTIAL_OBJECT, OTP_CREDENTIAL_OBJECT,
    hashed_password_material, otp_material,
};
use super::*;
use crate::credentials::{
    MAX_PASSWORD_BYTES, PasswordVerifier, PolicyDevice, PolicyUser, valid_username,
};
use std::sync::Arc;

/// Object Type enumeration (draft 3.0 table 582).
pub(super) const USER: u32 = 0x0b;
pub(super) const GROUP: u32 = 0x0c;
pub(super) const PASSWORD_CREDENTIAL_OBJECT: u32 = 0x0d;
/// Object Type of a Certificate credential System Object.
const CERTIFICATE_OBJECT: u32 = 1;
/// Hidden record of an obliterated User's name (outside the draft's Object
/// Type values; never returned to clients).
const RETIRED_USER: u32 = 0x8000_000b;
/// Credential Type enumeration (1.0 table 194 through draft 3.0 table 551).
const USERNAME_AND_PASSWORD: u32 = 1;
const DEVICE: u32 = 2;
const ATTESTATION: u32 = 3;
const ONE_TIME_PASSWORD: u32 = 4;
const HASHED_PASSWORD: u32 = 5;
const TICKET_CREDENTIAL: u32 = 6;
const PASSWORD_CREDENTIAL_TYPE: u32 = 7;
const CERTIFICATE_CREDENTIAL_TYPE: u32 = 8;
/// Result Reasons (draft 3.0 table 595).
const AUTHENTICATION_NOT_SUCCESSFUL: u32 = 3;
const MAX_CREDENTIAL_LINKS: usize = 8;

/// System Objects belong to the certificate principal, also when its
/// credential identities own managed objects separately.
pub(super) fn system_owner(owner: &str) -> String {
    format!("{}\0system", principal_of(owner))
}
const USER_OWNER: &str = "\0user\0";
const DEVICE_OWNER: &str = "\0device\0";
/// The certificate principal behind a managed-object owner: the owner itself,
/// or the principal of a credential identity (`principal\0user\0name`,
/// `principal\0device\0name`). Reserved namespaces such as System Objects
/// have none. Policy names never contain NUL, so the forms cannot collide.
pub(super) fn certificate_principal(owner: &str) -> Option<&str> {
    let Some((principal, rest)) = owner.split_once('\0') else {
        return Some(owner);
    };
    let rest = format!("\0{rest}");
    [USER_OWNER, DEVICE_OWNER]
        .iter()
        .any(|kind| {
            rest.strip_prefix(kind)
                .is_some_and(|name| !name.is_empty() && !name.contains('\0'))
        })
        .then_some(principal)
}
pub(super) fn principal_of(owner: &str) -> &str {
    certificate_principal(owner).unwrap_or(owner)
}

/// What the request-header credentials proved, within the certificate
/// principal: a user and/or a device, the ticket that proved them, and for
/// a delegated ticket the delegator's immutable context (tickets.rs).
#[derive(Clone, Default)]
pub(super) struct Identity {
    pub(super) user: Option<String>,
    pub(super) device: Option<String>,
    /// SHA-256 digest of the Ticket credential that authenticated the
    /// request, if any (Login or Delegated Login ticket).
    pub(super) ticket: Option<[u8; 32]>,
    /// The System credential that proved the user, or None for a users-file
    /// user.
    pub(super) credential: Option<String>,
    /// Set when a Delegated Login ticket authenticated the request: the
    /// request then acts as the delegator, within the ticket's Rights.
    pub(super) delegation: Option<Arc<tickets::Delegation>>,
}
impl Identity {
    /// The owner selected by credentials when the certificate principal uses
    /// credential identity (Profiles 2.0/2.1 section 3.1.3): the verified
    /// user, otherwise the verified device. Distinct from the principal
    /// itself, which remains the identity of requests without credentials.
    pub(super) fn owner(&self, principal: &str) -> String {
        match (&self.user, &self.device) {
            (Some(user), _) => format!("{principal}{USER_OWNER}{user}"),
            (None, Some(device)) => format!("{principal}{DEVICE_OWNER}{device}"),
            (None, None) => principal.to_owned(),
        }
    }
    /// Whether a delegated ticket (Delegated Login) proved this identity.
    pub(super) fn is_delegated(&self) -> bool {
        self.delegation.is_some()
    }
    /// Whether a ticket (Login or Delegated Login) authenticated this
    /// request.
    pub(super) fn is_ticket(&self) -> bool {
        self.ticket.is_some()
    }
    /// The audit principal: the certificate principal narrowed to the
    /// verified user and device (NUL never occurs in policy names). A
    /// delegated request records the delegator and the presenting
    /// principal: `delegator\0delegate\0presenter`.
    pub(super) fn audit_principal(&self, owner: &str) -> String {
        if let Some(delegation) = &self.delegation {
            return format!("{}\0delegate\0{owner}", delegation.delegator_audit);
        }
        let mut principal = owner.to_owned();
        if let Some(user) = &self.user {
            principal += &format!("\0user\0{user}");
        }
        if let Some(device) = &self.device {
            principal += &format!("\0device\0{device}");
        }
        principal
    }
}
pub(super) fn auth_failed() -> Failure {
    fail(
        AUTHENTICATION_NOT_SUCCESSFUL,
        "Authentication not successful",
    )
}
pub(super) fn name_of(obj: &Object) -> Option<&str> {
    obj.attrs
        .iter()
        .find(|a| a.tag == NAME)
        .and_then(|a| a.get(NAME_VALUE))
        .and_then(|n| n.string().ok())
}

impl Engine {
    /// Register operator-provisioned users of one certificate principal.
    /// A username that names a System User of the principal, current or
    /// obliterated, is refused: the two sources are never merged, and an
    /// obliterated user's identity is never reused.
    pub fn add_policy_users(&mut self, owner: &str, users: Vec<PolicyUser>) -> anyhow::Result<()> {
        crate::credentials::validate_users(&users)?;
        let system = system_owner(owner);
        for user in &users {
            let (count, _) = self.store.locate(&system, 0, 0, |o| {
                [USER, RETIRED_USER].contains(&o.object_type)
                    && name_of(o) == Some(user.username.as_str())
            })?;
            if count > 0 {
                anyhow::bail!(
                    "users file names {:?}, which is a current or obliterated System User",
                    user.username
                );
            }
        }
        self.policy_users.insert(owner.to_owned(), users);
        Ok(())
    }
    /// Opt one certificate principal into credential identity: requests
    /// whose header credentials verify act as, and own objects as, that user
    /// (or device) instead of the principal. Profiles 2.0/2.1 section 3.1.3:
    /// servers "SHALL use the identity derived from the Credential
    /// information to determine the client identity if the KMIP client
    /// requests contain an Authentication object". Requests without
    /// credentials keep the principal's identity. Off by default.
    pub fn use_credential_identity(&mut self, principal: &str) {
        self.credential_owners.insert(principal.to_owned());
    }
    /// The owner for this request: the delegator's owner under a delegated
    /// ticket; the credential identity when the principal opted in and
    /// credentials verified; otherwise the principal.
    pub(super) fn request_owner(&self, principal: &str) -> Option<String> {
        let identity = self.authorization.identity.as_ref()?;
        if let Some(delegation) = &identity.delegation {
            return Some(delegation.delegator_owner.clone());
        }
        self.credential_owners
            .contains(principal)
            .then(|| identity.owner(principal))
    }
    /// Register operator-provisioned devices of one certificate principal.
    pub fn add_policy_devices(
        &mut self,
        owner: &str,
        devices: Vec<PolicyDevice>,
    ) -> anyhow::Result<()> {
        crate::credentials::validate_devices(&devices)?;
        for device in &devices {
            if self.conflicts_with_system_device(owner, device)? {
                anyhow::bail!(
                    "policy device {:?} shares its name or identifiers with a System Device Credential",
                    device.name
                );
            }
        }
        self.policy_devices.insert(owner.to_owned(), devices);
        Ok(())
    }
    /// Request-header Authentication, every version.
    ///
    /// Profiles 1.1 section 3.1.3: "In the presence of Credential information
    /// in the request header, KMIP servers SHALL consider such Credential
    /// information into their evaluation of client authenticity and identity,
    /// along with the authenticity and identity derived from the channel."
    /// Profiles 1.2+ section 3.1.3 use the channel identity "along with the
    /// Credential information". Here the channel (mutual TLS) still selects the
    /// principal and ownership; every Credential must then verify against a
    /// user or device provisioned for that principal (2.0+ section 9.4 "they
    /// must ALL be satisfied"), or the message fails with Authentication Not
    /// Successful. A principal without provisioned users or devices therefore
    /// cannot present credentials at all: an unverifiable password is never
    /// treated as authentication. One Time Password and Hashed Password
    /// (2.0+) verify against users-file users and, in draft 3.0, against
    /// the credentials a System User links (credential_proofs.rs); a 3.0
    /// Device credential may also match a Device Credential System Object.
    /// A Ticket credential (2.0+) redeems a Login or Delegated Login ticket
    /// (tickets.rs): a Login ticket stands for the identity proved at Login,
    /// and may be combined with credentials of that same user or device; a
    /// delegated ticket must be the only credential and makes the request
    /// act as the delegator, without object grants. Credential types that
    /// cannot be verified here (Attestation) are refused, not ignored.
    pub(super) fn authenticate(
        &mut self,
        owner: &str,
        v: Version,
        header: &Node,
    ) -> R<Option<Identity>> {
        let Some(authentication) = header.get(AUTHENTICATION) else {
            return Ok(None);
        };
        // 1.0 and 1.1 table "Authentication Structure in Message Header":
        // one Credential; 1.2 and later: "one or more".
        let most = if v < Version(1, 2) { 1 } else { 4 };
        let credentials = authentication.children()?;
        if credentials.is_empty()
            || credentials.len() > most
            || credentials.iter().any(|c| c.tag != CREDENTIAL)
        {
            return Err(fail(7, "Invalid number of Credentials"));
        }
        let mut identity = Identity::default();
        for credential in credentials {
            no_fields(credential, &[CREDENTIAL_TYPE, CREDENTIAL_VALUE])?;
            let value = credential.required(CREDENTIAL_VALUE)?;
            let (user, proof) = match credential.required(CREDENTIAL_TYPE)?.number()? {
                USERNAME_AND_PASSWORD => self.verify_password(owner, value)?,
                DEVICE if v >= Version(1, 1) => {
                    let device = self.verify_device(owner, v, value)?;
                    if identity.device.as_ref().is_some_and(|d| *d != device) {
                        return Err(auth_failed());
                    }
                    identity.device = Some(device);
                    continue;
                }
                TICKET_CREDENTIAL if v.0 >= 2 => {
                    // At most one ticket per request.
                    if identity.ticket.is_some() {
                        return Err(auth_failed());
                    }
                    let (digest, ticket) =
                        self.redeem_ticket(owner, v, value, credentials.len() == 1)?;
                    identity.ticket = Some(digest);
                    if let Some(delegation) = ticket.delegation() {
                        // The delegate acts as the delegator, whose object
                        // grants, like the presenter's, do not apply.
                        identity.delegation = Some(delegation);
                        self.authorization.grants.clear();
                        continue;
                    }
                    if let Some(device) = ticket.device() {
                        if identity.device.as_ref().is_some_and(|d| d != device) {
                            return Err(auth_failed());
                        }
                        identity.device = Some(device.to_owned());
                    }
                    let Some(user) = ticket.user() else {
                        continue;
                    };
                    (user.to_owned(), ticket.credential().map(str::to_owned))
                }
                // 1.2+ Attestation: the Nonce must come from this server
                // and the measurement or assertion formats (TPM Quote, TCG
                // Integrity Report, SAML Assertion) are defined elsewhere
                // with no verification procedure in KMIP, so it stays
                // refused (docs/credentials.md).
                ATTESTATION if v >= Version(1, 2) => {
                    return Err(fail(8, "Credential Type is not supported"));
                }
                ONE_TIME_PASSWORD if v.0 >= 2 => self.verify_one_time_password(owner, v, value)?,
                HASHED_PASSWORD if v.0 >= 2 => {
                    let (user, proof, server) = self.verify_hashed_password(owner, v, value)?;
                    self.authorization.server_hashed_password = Some(server);
                    (user, proof)
                }
                PASSWORD_CREDENTIAL_TYPE | CERTIFICATE_CREDENTIAL_TYPE if v.0 >= 3 => {
                    return Err(fail(8, "Credential Type is not supported"));
                }
                _ => return Err(fail(7, "Invalid Credential Type")),
            };
            if identity.user.as_ref().is_some_and(|u| *u != user) {
                return Err(auth_failed());
            }
            identity.user = Some(user);
            identity.credential = proof;
        }
        Ok(Some(identity))
    }
    /// Whether the principal has any user or device a credential could name.
    /// Without one there is no username to protect from enumeration, so a
    /// failure needs no verifier derivation.
    pub(super) fn has_users(&self, owner: &str) -> R<bool> {
        if self.policy_users.get(owner).is_some_and(|u| !u.is_empty()) {
            return Ok(true);
        }
        let (count, _) = self
            .store
            .locate(&system_owner(owner), 0, 0, |o| o.object_type == USER)?;
        Ok(count > 0)
    }
    /// The verifier derivations `authenticate` will need for this request,
    /// found while the engine is locked so that they can run unlocked
    /// (`credentials::Work::run`). Mirrors `verify_password` and
    /// `verify_device`; anything it misses is evaluated during the request.
    pub fn credential_work(
        &self,
        owner: &str,
        request: &Node,
        allowed: Option<&[u32]>,
    ) -> crate::credentials::Work {
        let _fips = crate::fips::enter(self.fips);
        let _curves = crate::crypto::ec::enter(self.curve_set());
        let mut work = crate::credentials::Work::default();
        if allowed.is_some_and(<[u32]>::is_empty) {
            return work;
        }
        let header = request.get(REQUEST_HEADER);
        // System credentials verify only in draft 3.0 (`authenticate`).
        let v = header
            .and_then(|h| h.get(PROTOCOL_VERSION))
            .and_then(|n| Version::read(n).ok())
            .unwrap_or(Version(1, 0));
        let credentials = header
            .and_then(|h| h.get(AUTHENTICATION))
            .and_then(|a| a.children().ok())
            .unwrap_or(&[]);
        for credential in credentials.iter().take(4) {
            let Some(value) = credential.get(CREDENTIAL_VALUE) else {
                continue;
            };
            let kind = credential
                .get(CREDENTIAL_TYPE)
                .and_then(|n| n.number().ok());
            if let Some(kind @ (ONE_TIME_PASSWORD | HASHED_PASSWORD)) = kind {
                self.proof_work(owner, v, kind, value, &mut work);
                continue;
            }
            let Some(password) = value.get(PASSWORD).and_then(|n| n.string().ok()) else {
                continue;
            };
            let password = password.as_bytes();
            if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
                continue;
            }
            match credential
                .get(CREDENTIAL_TYPE)
                .and_then(|n| n.number().ok())
            {
                Some(USERNAME_AND_PASSWORD) => {
                    let Some(username) = value.get(USERNAME).and_then(|n| n.string().ok()) else {
                        continue;
                    };
                    match self.user_verifiers(owner, username) {
                        Ok(found) if !found.is_empty() => {
                            for (_, verifier) in &found {
                                work.verify(verifier, password);
                            }
                        }
                        Ok(_) if self.has_users(owner).unwrap_or(false) => work.burn(password),
                        _ => {}
                    }
                }
                Some(DEVICE) => match self.device_verifier(owner, v, value) {
                    Ok(Some((_, verifier))) => work.verify(&verifier, password),
                    Ok(None) if self.has_devices(owner, v).unwrap_or(false) => work.burn(password),
                    _ => {}
                },
                _ => {}
            }
        }
        work
    }
    /// Returns the username and the System credential that verified it.
    fn verify_password(&self, owner: &str, value: &Node) -> R<(String, Option<String>)> {
        no_fields(value, &[USERNAME, PASSWORD])?;
        let username = value.required(USERNAME)?.string()?;
        // Table "Credential Value Structure for the Username and Password
        // Credential" makes Password optional, but a password-less credential
        // carries no proof, so it never authenticates here.
        let password = value
            .get(PASSWORD)
            .map(Node::string)
            .transpose()?
            .unwrap_or_default()
            .as_bytes();
        let verifiers = if valid_username(username)
            && !password.is_empty()
            && password.len() <= MAX_PASSWORD_BYTES
        {
            self.user_verifiers(owner, username)?
        } else {
            vec![]
        };
        if verifiers.is_empty() {
            if self.has_users(owner)? {
                PasswordVerifier::burn(password);
            }
            return Err(auth_failed());
        }
        // Every verifier is evaluated, so timing does not depend on which
        // one matches. New users have one password credential.
        let mut matched = None;
        for (credential, verifier) in verifiers {
            if verifier.verify(password) && matched.is_none() {
                matched = Some(credential);
            }
        }
        match matched {
            Some(credential) => Ok((username.to_owned(), credential)),
            None => Err(auth_failed()),
        }
    }
    /// KMIP 1.1+ section 2.1.2 Device credential: "The client SHALL provide
    /// at least one field." The identifiers select a provisioned device, or
    /// in draft 3.0 a Device Credential System Object, only on an exact
    /// match of every identifier; the password then proves it.
    fn verify_device(&self, owner: &str, v: Version, value: &Node) -> R<String> {
        const FIELDS: [u32; 5] = [
            DEVICE_SERIAL_NUMBER,
            DEVICE_IDENTIFIER,
            NETWORK_IDENTIFIER,
            MACHINE_IDENTIFIER,
            MEDIA_IDENTIFIER,
        ];
        let mut allowed = FIELDS.to_vec();
        allowed.push(PASSWORD);
        no_fields(value, &allowed)?;
        if value.children()?.is_empty() {
            return Err(fail(7, "A Device credential requires at least one field"));
        }
        for tag in FIELDS {
            value.get(tag).map(Node::string).transpose()?;
        }
        let password = value
            .get(PASSWORD)
            .map(Node::string)
            .transpose()?
            .unwrap_or_default()
            .as_bytes();
        let device = if !password.is_empty() && password.len() <= MAX_PASSWORD_BYTES {
            self.device_verifier(owner, v, value)?
        } else {
            None
        };
        match device {
            Some((name, verifier)) if verifier.verify(password) => Ok(name),
            Some(_) => Err(auth_failed()),
            None => {
                if self.has_devices(owner, v)? {
                    PasswordVerifier::burn(password);
                }
                Err(auth_failed())
            }
        }
    }
    /// The device the presented identifiers select and its password
    /// verifier: a provisioned device, otherwise (3.0) a System Device
    /// Credential whose Password Credential still exists.
    fn device_verifier(
        &self,
        owner: &str,
        v: Version,
        value: &Node,
    ) -> R<Option<(String, PasswordVerifier)>> {
        if let Some(device) = self.find_device(owner, value) {
            return Ok(Some((device.name.clone(), device.password_scrypt.clone())));
        }
        if v.0 < 3 {
            return Ok(None);
        }
        let presented = [
            DEVICE_SERIAL_NUMBER,
            DEVICE_IDENTIFIER,
            NETWORK_IDENTIFIER,
            MACHINE_IDENTIFIER,
            MEDIA_IDENTIFIER,
        ]
        .map(|tag| value.get(tag).and_then(|n| n.string().ok()));
        Ok(self
            .system_device(owner, &presented)?
            .and_then(|(id, verifier)| Some((id, verifier?))))
    }
    /// The provisioned device whose identifiers all equal the presented ones.
    fn find_device(&self, owner: &str, value: &Node) -> Option<&PolicyDevice> {
        let presented = [
            DEVICE_SERIAL_NUMBER,
            DEVICE_IDENTIFIER,
            NETWORK_IDENTIFIER,
            MACHINE_IDENTIFIER,
            MEDIA_IDENTIFIER,
        ]
        .map(|tag| value.get(tag).and_then(|n| n.string().ok()));
        self.policy_devices
            .get(owner)
            .into_iter()
            .flatten()
            .find(|d| {
                d.identifiers()
                    .iter()
                    .zip(&presented)
                    .all(|(configured, presented)| configured.as_deref() == *presented)
            })
    }
    /// The verifiers of one username, from exactly one source: the users
    /// file if it names the user, otherwise the System User's password
    /// credentials (with their identifiers).
    fn user_verifiers(
        &self,
        owner: &str,
        username: &str,
    ) -> R<Vec<(Option<String>, PasswordVerifier)>> {
        if let Some(user) = self
            .policy_users
            .get(owner)
            .into_iter()
            .flatten()
            .find(|u| u.username == username)
        {
            return Ok(vec![(None, user.password_scrypt.clone())]);
        }
        let mut verifiers = vec![];
        let system = system_owner(owner);
        let (_, users) = self.store.locate(&system, 0, 1, |o| {
            o.object_type == USER && name_of(o) == Some(username)
        })?;
        for id in users {
            let Some(user) = self.store.get(&system, &id)? else {
                continue;
            };
            for link in user.attrs.iter().filter(|a| a.tag == CREDENTIAL_LINK) {
                if let Ok(target) = link.identifier_text()
                    && let Some(credential) = self.store.get(&system, target)?
                    && credential.object_type == PASSWORD_CREDENTIAL_OBJECT
                {
                    let verifier: PasswordVerifier =
                        serde_json::from_slice(&credential.material)
                            .map_err(|_| fail(0x2a, "Stored password verifier is unreadable"))?;
                    verifiers.push((Some(credential.id.clone()), verifier));
                }
            }
        }
        Ok(verifiers)
    }
    /// Whether a proof recorded earlier (a Login ticket or a queued
    /// asynchronous request) still names a current user or device: the
    /// users-file user or device is still provisioned, or the System User
    /// still links the System credential that proved it.
    /// A ticket-proved identity also needs its ticket alive: not expired,
    /// logged out or revoked (an exhausted Request Count does not matter).
    pub(super) fn identity_current(&self, owner: &str, identity: &Identity) -> R<bool> {
        if identity
            .ticket
            .is_some_and(|digest| !self.tickets.live(&digest))
        {
            return Ok(false);
        }
        if let Some(device) = &identity.device
            && !self
                .policy_devices
                .get(owner)
                .is_some_and(|d| d.iter().any(|d| d.name == *device))
            && !self.system_device_current(owner, device)?
        {
            return Ok(false);
        }
        match &identity.user {
            None => Ok(true),
            Some(user) => self.proof_current(owner, user, identity.credential.as_deref()),
        }
    }
    pub(super) fn proof_current(
        &self,
        owner: &str,
        user: &str,
        credential: Option<&str>,
    ) -> R<bool> {
        let policy = self
            .policy_users
            .get(owner)
            .is_some_and(|users| users.iter().any(|u| u.username == user));
        let Some(credential) = credential else {
            return Ok(policy);
        };
        if policy {
            return Ok(false);
        }
        // Any credential that proved the user: Password, One Time Password
        // or Hashed Password Credential.
        Ok(self
            .user_links(owner, user)?
            .iter()
            .any(|id| id == credential))
    }
    /// The verified user; a device credential alone does not name one.
    fn require_identity(&self) -> R<&str> {
        self.authorization
            .identity
            .as_ref()
            .and_then(|i| i.user.as_deref())
            .ok_or(fail(
                12,
                "System Objects require a verified user credential in the request header",
            ))
    }
    /// Creating and obliterating System Objects is reserved to users-file
    /// users marked `administrator` (Permission Denied otherwise).
    fn require_administrator(&self, owner: &str) -> R<()> {
        let user = self.require_identity()?;
        let administrator = self
            .authorization
            .identity
            .as_ref()
            .is_some_and(|i| i.credential.is_none())
            && self
                .policy_users
                .get(principal_of(owner))
                .is_some_and(|users| users.iter().any(|u| u.username == user && u.administrator));
        if administrator {
            Ok(())
        } else {
            Err(fail(
                12,
                "System Objects require an administrator credential in the request header",
            ))
        }
    }
    fn system_object(owner: &str, kind: u32, attrs: Vec<Node>, material: Vec<u8>) -> Object {
        let time = now();
        Object {
            id: crypto::uuid(),
            owner: system_owner(owner),
            object_type: kind,
            secret_type: 2,
            opaque_type: opaque::LEGACY_TYPE,
            pgp_version: pgp::DEFAULT_VERSION,
            certificate_type: 1,
            format: 0,
            algorithm: 0,
            bits: 0,
            usage: 0,
            protection_mask: protection::SOFTWARE,
            usage_consumed: false,
            replacement_id: None,
            wrapped: None,
            imported: false,
            metadata: Default::default(),
            split: None,
            state: 1,
            material,
            attrs,
            attribute_indices: Default::default(),
            created: time,
            updated: time,
        }
    }
    /// Shared attribute rules for Create User, Create Group and Create
    /// Credential: one Uninterpreted Text String Name, unique among this
    /// principal's System Objects of the same type, plus an optional Comment.
    fn system_attrs(
        &self,
        owner: &str,
        v: Version,
        kind: u32,
        p: &Node,
        name_required: bool,
        mut extra: impl FnMut(&Node) -> R<Option<Node>>,
    ) -> R<Vec<Node>> {
        let mut attrs = vec![];
        for a in read_attrs(p, v)? {
            match a.tag {
                NAME | COMMENT if attrs.iter().any(|b: &Node| b.tag == a.tag) => {
                    return Err(fail(0x23, "Attribute is single valued"));
                }
                NAME => {
                    no_fields(&a, &[NAME_VALUE, NAME_TYPE])?;
                    if number(&a, NAME_TYPE, 1)? != 1
                        || !valid_username(a.required(NAME_VALUE)?.string()?)
                    {
                        return Err(fail(0x2d, "Invalid System Object Name"));
                    }
                    attrs.push(a);
                }
                COMMENT => {
                    a.string()?;
                    attrs.push(a);
                }
                CREDENTIAL_TYPE => return Err(usage::read_only(v)),
                _ => match extra(&a)? {
                    Some(a) => attrs.push(a),
                    // Unsupported Attribute (draft 3.0 tables 279, 282, 292).
                    None => return Err(fail(0x1f, "Attribute is not supported")),
                },
            }
        }
        attributes::limits(&attrs)?;
        let name = attrs
            .iter()
            .find(|a| a.tag == NAME)
            .and_then(|a| a.get(NAME_VALUE))
            .and_then(|n| n.string().ok())
            .map(str::to_owned);
        match name {
            None if name_required => return Err(fail(7, "A Name attribute is required")),
            None => {}
            Some(name) => {
                let system = system_owner(owner);
                // An obliterated User's name is retired with it.
                let (count, _) = self.store.locate(&system, 0, 0, |o| {
                    (o.object_type == kind || kind == USER && o.object_type == RETIRED_USER)
                        && name_of(o) == Some(name.as_str())
                })?;
                let policy = kind == USER
                    && self
                        .policy_users
                        .get(principal_of(owner))
                        .is_some_and(|users| users.iter().any(|u| u.username == name));
                if count > 0 || policy {
                    return Err(fail(0x35, "Name is not unique"));
                }
            }
        }
        Ok(attrs)
    }
    fn insert_system(&self, obj: Object, placeholder: &mut Option<String>) -> R<Vec<Node>> {
        self.store.insert(&obj)?;
        *placeholder = Some(obj.id.clone());
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
    /// Draft 3.0 section 6.1.13 and table 3: a User has a Name, which is its
    /// username, and at least one Credential Link to a credential of this
    /// principal created with Create Credential.
    pub(super) fn create_user(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        self.require_administrator(owner)?;
        no_fields(p, &[ATTRIBUTES])?;
        p.required(ATTRIBUTES)?;
        let system = system_owner(owner);
        let attrs = self.system_attrs(owner, v, USER, p, true, |a| {
            if a.tag != CREDENTIAL_LINK {
                return Ok(None);
            }
            let target = match &a.value {
                Value::Reference(id) if !id.is_empty() => id,
                Value::NameReference(_) => {
                    return Err(fail(8, "Credential Link name references are not supported"));
                }
                _ => return Err(fail(0x2d, "Invalid Credential Link")),
            };
            let credential = self
                .store
                .get(&system, target)?
                .ok_or(fail(0x2d, "Credential Link target not found"))?;
            if ![
                PASSWORD_CREDENTIAL_OBJECT,
                CERTIFICATE_OBJECT,
                DEVICE_CREDENTIAL_OBJECT,
                OTP_CREDENTIAL_OBJECT,
                HASHED_PASSWORD_CREDENTIAL_OBJECT,
            ]
            .contains(&credential.object_type)
            {
                return Err(fail(0x2d, "Credential Link target is not a credential"));
            }
            Ok(Some(Node::reference(CREDENTIAL_LINK, target)))
        })?;
        let links = attrs.iter().filter(|a| a.tag == CREDENTIAL_LINK).count();
        if links == 0 || links > MAX_CREDENTIAL_LINKS {
            return Err(fail(7, "A User requires one to eight Credential Links"));
        }
        // One credential of each verifiable kind per user keeps every check
        // to one verifier derivation, the cost of an unknown username. A
        // Device Credential names a device, never this user.
        let mut kinds = vec![];
        for a in attrs.iter().filter(|a| a.tag == CREDENTIAL_LINK) {
            if let Ok(target) = a.identifier_text()
                && let Some(c) = self.store.get(&system, target)?
            {
                kinds.push(c.object_type);
            }
        }
        for kind in [
            PASSWORD_CREDENTIAL_OBJECT,
            OTP_CREDENTIAL_OBJECT,
            HASHED_PASSWORD_CREDENTIAL_OBJECT,
        ] {
            if kinds.iter().filter(|k| **k == kind).count() > 1 {
                return Err(fail(
                    0x3a,
                    "A User may link at most one Password, One Time Password and Hashed Password Credential",
                ));
            }
        }
        self.insert_system(Self::system_object(owner, USER, attrs, vec![]), placeholder)
    }
    /// Draft 3.0 section 6.1.10 and table 4: a Group has a required Name.
    pub(super) fn create_group(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        self.require_administrator(owner)?;
        no_fields(p, &[ATTRIBUTES])?;
        p.required(ATTRIBUTES)?;
        let attrs = self.system_attrs(owner, v, GROUP, p, true, |_| Ok(None))?;
        self.insert_system(
            Self::system_object(owner, GROUP, attrs, vec![]),
            placeholder,
        )
    }
    /// Draft 3.0 section 6.1.9. Password credentials (section 2.1.3.1) keep
    /// only a password verifier, never the plaintext. The pre-salted form and
    /// Password Link are refused: the draft does not define the salting
    /// algorithm, and a linked Secret Data object would hold the plaintext.
    /// A Certificate credential keeps the DER certificate as a System Object.
    /// Device, One Time Password and Hashed Password credentials (sections
    /// 2.1.3.2-2.1.3.4) are in system_credentials.rs; a Device Credential
    /// takes its secret from a Password Link to a Password Credential.
    pub(super) fn create_credential(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        self.require_administrator(owner)?;
        let values = [
            PASSWORD_CREDENTIAL,
            DEVICE_CREDENTIAL,
            HASHED_PASSWORD_CREDENTIAL,
            OTP_CREDENTIAL,
            CERTIFICATE,
        ];
        let mut allowed = vec![CREDENTIAL_TYPE, ATTRIBUTES];
        allowed.extend(values);
        no_fields(p, &allowed)?;
        p.required(ATTRIBUTES)?;
        let kind = p.required(CREDENTIAL_TYPE)?.number()?;
        if values.iter().filter(|t| p.get(**t).is_some()).count() != 1 {
            return Err(fail(7, "Exactly one credential value is required"));
        }
        let (object_type, material) = match kind {
            PASSWORD_CREDENTIAL_TYPE => {
                let value = p
                    .get(PASSWORD_CREDENTIAL)
                    .ok_or(fail(7, "Password Credential value is required"))?;
                no_fields(
                    value,
                    &[
                        PASSWORD,
                        PASSWORD_SALT,
                        PASSWORD_SALT_ALGORITHM,
                        SALTED_PASSWORD,
                        ITERATION_COUNT,
                    ],
                )?;
                if [
                    PASSWORD_SALT,
                    PASSWORD_SALT_ALGORITHM,
                    SALTED_PASSWORD,
                    ITERATION_COUNT,
                ]
                .iter()
                .any(|t| value.get(*t).is_some())
                {
                    return Err(fail(8, "Pre-salted password credentials are not supported"));
                }
                let password = value.required(PASSWORD)?.string()?;
                let verifier = PasswordVerifier::new(password.as_bytes())
                    .map_err(|_| fail(0x2d, "Password length is outside the accepted range"))?;
                let material = serde_json::to_vec(&verifier).map_err(anyhow::Error::from)?;
                (PASSWORD_CREDENTIAL_OBJECT, material)
            }
            CERTIFICATE_CREDENTIAL_TYPE => {
                let value = p
                    .get(CERTIFICATE)
                    .ok_or(fail(7, "Certificate value is required"))?;
                no_fields(value, &[CERTIFICATE_TYPE, CERTIFICATE_VALUE])?;
                if value.required(CERTIFICATE_TYPE)?.number()? != 1 {
                    return Err(fail(8, "Only X.509 certificate credentials are supported"));
                }
                let der = value.required(CERTIFICATE_VALUE)?.byte_string()?;
                if der.len() > crate::certificates::MAX_BYTES
                    || !openssl::x509::X509::from_der(der)
                        .and_then(|c| c.to_der())
                        .is_ok_and(|round| round == der)
                {
                    return Err(fail(7, "Invalid X.509 certificate"));
                }
                (CERTIFICATE_OBJECT, der.to_vec())
            }
            DEVICE => {
                let value = p
                    .get(DEVICE_CREDENTIAL)
                    .ok_or(fail(7, "Device Credential value is required"))?;
                (
                    DEVICE_CREDENTIAL_OBJECT,
                    self.device_credential_material(owner, value)?,
                )
            }
            ONE_TIME_PASSWORD => {
                let value = p
                    .get(OTP_CREDENTIAL)
                    .ok_or(fail(7, "OTP Credential value is required"))?;
                (OTP_CREDENTIAL_OBJECT, otp_material(value)?)
            }
            HASHED_PASSWORD => {
                let value = p
                    .get(HASHED_PASSWORD_CREDENTIAL)
                    .ok_or(fail(7, "Hashed Password Credential value is required"))?;
                (
                    HASHED_PASSWORD_CREDENTIAL_OBJECT,
                    hashed_password_material(value)?,
                )
            }
            // Username and Password, Attestation and Ticket name no System
            // Object (sections 2.1.3.1-2.1.3.4).
            1..=6 => return Err(fail(8, "Credential Type is not supported")),
            _ => return Err(fail(7, "Invalid Credential Type")),
        };
        let mut attrs = self.system_attrs(owner, v, object_type, p, false, |a| match a.tag {
            PASSWORD_LINK if kind == DEVICE => self.device_password_link(owner, a).map(Some),
            PASSWORD_LINK => Err(fail(8, "Password Link is not supported")),
            // Table 186: OTP Counter is set by the server only.
            OTP_COUNTER => Err(usage::read_only(v)),
            _ => Ok(None),
        })?;
        if kind == DEVICE {
            // Identifiers are not secrets (table 7 carries no password), so
            // a device without a Password Link could never authenticate.
            match attrs.iter().filter(|a| a.tag == PASSWORD_LINK).count() {
                1 => {}
                0 => {
                    return Err(fail(
                        8,
                        "A Device Credential without a Password Link is not supported",
                    ));
                }
                _ => return Err(fail(8, "Multiple Password Links are not supported")),
            }
        }
        attrs.push(Node::enumeration(CREDENTIAL_TYPE, kind));
        self.insert_system(
            Self::system_object(owner, object_type, attrs, material),
            placeholder,
        )
    }
    /// Draft 3.0 section 6.1.41: remove the object and all of its metadata;
    /// later references return Item Not Found and the identifier may be
    /// reused. Unlike Destroy (section 6.1.20) no lifecycle state applies and
    /// nothing remains readable. Special authorization is the certificate
    /// policy's explicit grant of operation 61; System Objects additionally
    /// require an administrator. Obliterating a User retires its name and
    /// revokes its tickets; obliterating a credential revokes the tickets it
    /// proved. The tamper-evident audit log keeps the event that names the
    /// identifier.
    pub(super) fn obliterate(
        &mut self,
        owner: &str,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(p, &[UNIQUE_IDENTIFIER])?;
        let id = match p.get(UNIQUE_IDENTIFIER) {
            Some(n) => n.string()?.to_owned(),
            None => placeholder
                .clone()
                .ok_or(fail(6, "Unique Identifier or ID Placeholder required"))?,
        };
        if self.store.get(owner, &id)?.is_some() {
            self.store.remove(owner, &id)?;
            self.streams.invalidate_key(owner, &id);
            return Ok(vec![]);
        }
        let system = system_owner(owner);
        let Some(target) = self
            .store
            .get(&system, &id)?
            .filter(|o| o.object_type != RETIRED_USER)
        else {
            // Draft 3.0 6.1.41 and Table 376: Object Not Found (see not_found.rs).
            return Err(not_found::object());
        };
        self.require_administrator(owner)?;
        self.store.remove(&system, &id)?;
        let principal = principal_of(owner).to_owned();
        if target.object_type == USER
            && let Some(name) = name_of(&target)
        {
            let name = name.to_owned();
            let retired = Self::system_object(
                &principal,
                RETIRED_USER,
                vec![Node::structure(
                    NAME,
                    vec![
                        Node::text(NAME_VALUE, &name),
                        Node::enumeration(NAME_TYPE, 1),
                    ],
                )],
                vec![],
            );
            self.store.insert(&retired)?;
            self.tickets.revoke_user(&principal, &name);
        } else {
            self.tickets.revoke_credential(&principal, &id);
        }
        Ok(vec![])
    }
}

/// Draft 3.0 section 4.35.7: Group Link is a multi-instance link to a group by
/// Reference (early binding) or Name Reference (late binding). The target need
/// not exist (section 4.35), so arbitrary group names are accepted.
pub(super) fn validate_group_link(a: &Node, v: Version) -> R<()> {
    if v.0 < 3 {
        return Err(fail(8, "Attribute is not supported"));
    }
    match &a.value {
        Value::Reference(id) | Value::NameReference(id) if !id.is_empty() => Ok(()),
        _ => Err(fail(7, "Invalid Group Link")),
    }
}
