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

//! Draft 3.0 (CSD02) Device, One Time Password and Hashed Password Credential
//! System Objects (sections 2.1.3.2-2.1.3.4, tables 7-12) and the lookups
//! that let request-header credentials verify against them in 3.0.
//!
//! What is stored, sealed in the encrypted store like every System Object:
//!
//! * Device Credential: the identifiers of table 7. Identifiers are not
//!   secrets, and table 7 has no password field, so the secret is the
//!   Password Link attribute (section 4.35.11: "The Password Link target
//!   object will typically be ... a Password Credential") naming a Password
//!   Credential of the same principal, which holds only a password verifier.
//! * One Time Password Credential: the TOTP seed and parameters of table 9
//!   (`TotpSecret`, the same verification as the 2.x users-file path).
//! * Hashed Password Credential: S1 as is and a password verifier of S2
//!   (`HashedPasswordSecret`, table 11), as for users-file users.
//!
//! None of these objects is reachable by Get, Get Attributes or Locate: they
//! live in the per-principal System namespace (system.rs).
use super::system::{PASSWORD_CREDENTIAL_OBJECT, USER, name_of, system_owner};
use super::*;
use crate::credentials::{
    HashName, HashedPasswordSecret, PasswordVerifier, PolicyDevice, TotpDigest, TotpSecret,
    valid_username,
};
use serde::{Deserialize, Serialize};

/// Object Type enumeration (draft 3.0 table 582).
pub(super) const DEVICE_CREDENTIAL_OBJECT: u32 = 0x0e;
pub(super) const OTP_CREDENTIAL_OBJECT: u32 = 0x0f;
pub(super) const HASHED_PASSWORD_CREDENTIAL_OBJECT: u32 = 0x10;
/// OTP Algorithm enumeration (draft 3.0 table 586).
const HOTP: u32 = 1;
const TOTP: u32 = 2;
/// Cryptographic Algorithm values accepted as OTP Digest (table 551 has no
/// plain SHA-1/SHA-2 values; TOTP is an HMAC construction, RFC 6238 1.2).
const HMAC_SHA1: u32 = 7;
const HMAC_SHA256: u32 = 9;
const HMAC_SHA512: u32 = 0x0b;

/// Device identifier fields in table 7 order; the same as the request
/// Device credential (table 520) without its Password.
const DEVICE_FIELDS: [u32; 5] = [
    DEVICE_SERIAL_NUMBER,
    DEVICE_IDENTIFIER,
    NETWORK_IDENTIFIER,
    MACHINE_IDENTIFIER,
    MEDIA_IDENTIFIER,
];
type Identifiers = [Option<String>; 5];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceMaterial {
    identifiers: Identifiers,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OtpMaterial {
    totp: TotpSecret,
    #[serde(default)]
    serial: Option<String>,
}

/// "One or a combination of the Device Serial Number, Network Identifier,
/// Machine Identifier, and Media Identifier SHALL be unique" (2.1.3.2).
fn unique_part<T>(ids: &[T; 5]) -> [&T; 4] {
    [&ids[0], &ids[2], &ids[3], &ids[4]]
}
fn policy_identifiers(device: &PolicyDevice) -> Identifiers {
    device.identifiers().map(Clone::clone)
}
fn unreadable() -> Failure {
    fail(0x2a, "Stored credential is unreadable")
}
fn device_material(obj: &Object) -> Option<Identifiers> {
    (obj.object_type == DEVICE_CREDENTIAL_OBJECT)
        .then(|| serde_json::from_slice::<DeviceMaterial>(&obj.material).ok())
        .flatten()
        .map(|m| m.identifiers)
}
fn password_link(obj: &Object) -> Option<&str> {
    obj.attrs
        .iter()
        .find(|a| a.tag == PASSWORD_LINK)
        .and_then(|a| a.identifier_text().ok())
}

/// The credentials a System User links, at most one of each kind
/// (`Engine::create_user` enforces this).
#[derive(Default)]
pub(super) struct UserCredentials {
    pub password: Option<(String, PasswordVerifier)>,
    pub otp: Option<(String, TotpSecret)>,
    pub hashed: Option<(String, HashedPasswordSecret)>,
}

/// Draft 3.0 table 11. The client supplies S1 = Hash(Username || Password)
/// and S2 = Hash(Password || Username); the server keeps S1 (needed to
/// recompute Hash(S1 || Timestamp)) and only a password verifier of S2.
pub(super) fn hashed_password_material(value: &Node) -> R<Vec<u8>> {
    no_fields(
        value,
        &[
            HASHING_ALGORITHM,
            HASHED_USERNAME_PASSWORD,
            HASHED_PASSWORD_USERNAME,
        ],
    )?;
    // 2.1.3.4: "The Hashing Algorithm SHALL default to SHA 256."
    let algorithm = match value.get(HASHING_ALGORITHM).map(Node::number).transpose()? {
        None | Some(6) => HashName::Sha256,
        Some(7) => HashName::Sha384,
        Some(8) => HashName::Sha512,
        // MD5, SHA-1 and others are refused as for users-file users.
        Some(_) => return Err(fail(8, "Hashing Algorithm is not supported")),
    };
    let s1 = value.required(HASHED_USERNAME_PASSWORD)?.byte_string()?;
    let s2 = value.required(HASHED_PASSWORD_USERNAME)?.byte_string()?;
    let len = algorithm.output_len();
    if s1.len() != len || s2.len() != len {
        return Err(fail(7, "Hashed values do not match the Hashing Algorithm"));
    }
    let secret = HashedPasswordSecret {
        hashing_algorithm: algorithm,
        s1: s1.to_vec(),
        s2_scrypt: PasswordVerifier::new(s2).map_err(|_| fail(7, "Invalid Hashed Password"))?,
    };
    Ok(serde_json::to_vec(&secret).map_err(anyhow::Error::from)?)
}

/// Draft 3.0 table 9. Only TOTP (RFC 6238) is offered, as on the 2.x path:
/// an HOTP counter could not be trusted after a restore. The seed must be
/// supplied, since the Create Credential response (table 278) carries only
/// the Unique Identifier and could not return a server-generated seed.
pub(super) fn otp_material(value: &Node) -> R<Vec<u8>> {
    no_fields(
        value,
        &[
            OTP_ALGORITHM,
            OTP_DIGEST,
            OTP_SERIAL,
            OTP_SEED,
            OTP_INTERVAL,
            OTP_DIGITS,
        ],
    )?;
    match value.required(OTP_ALGORITHM)?.number()? {
        TOTP => {}
        HOTP => return Err(fail(8, "HOTP credentials are not supported")),
        _ => return Err(fail(7, "Invalid OTP Algorithm")),
    }
    let digest = match value.get(OTP_DIGEST).map(Node::number).transpose()? {
        // RFC 6238 section 1.2 and 4: HMAC-SHA-1 unless stated otherwise.
        None | Some(HMAC_SHA1) => TotpDigest::Sha1,
        Some(HMAC_SHA256) => TotpDigest::Sha256,
        Some(HMAC_SHA512) => TotpDigest::Sha512,
        Some(_) => return Err(fail(8, "OTP Digest is not supported")),
    };
    let seed = value
        .get(OTP_SEED)
        .ok_or(fail(8, "Server-generated OTP seeds are not supported"))?
        .byte_string()?;
    let interval = match value.get(OTP_INTERVAL).map(|n| &n.value) {
        None => 30,
        Some(Value::Interval(seconds)) => *seconds,
        Some(_) => return Err(fail(7, "OTP Interval must be an Interval")),
    };
    let digits = match value.get(OTP_DIGITS).map(|n| &n.value) {
        None => 6,
        Some(Value::Integer(digits)) => {
            u32::try_from(*digits).map_err(|_| fail(7, "Invalid OTP Digits"))?
        }
        Some(_) => return Err(fail(7, "OTP Digits must be an Integer")),
    };
    let serial = value
        .get(OTP_SERIAL)
        .map(|n| n.string().map(str::to_owned))
        .transpose()?;
    if serial.as_deref().is_some_and(|s| !valid_username(s)) {
        return Err(fail(7, "Invalid OTP Serial"));
    }
    let totp = TotpSecret {
        seed: seed.to_vec(),
        digest,
        digits,
        interval,
    };
    // At least 128-bit seeds (RFC 4226 R6), 6-8 digits, 15-300 s steps.
    totp.validate().map_err(|_| {
        fail(
            7,
            "OTP seed, digits or interval are outside the accepted range",
        )
    })?;
    Ok(serde_json::to_vec(&OtpMaterial { totp, serial }).map_err(anyhow::Error::from)?)
}

impl Engine {
    /// Draft 3.0 table 7. "The client SHALL provide at least one field", and
    /// the unique part (serial, network, machine, media identifier) must
    /// differ from every device of the principal, provisioned or System.
    pub(super) fn device_credential_material(&self, owner: &str, value: &Node) -> R<Vec<u8>> {
        no_fields(value, &DEVICE_FIELDS)?;
        let mut identifiers: Identifiers = Default::default();
        for (slot, tag) in identifiers.iter_mut().zip(DEVICE_FIELDS) {
            if let Some(n) = value.get(tag) {
                let text = n.string()?;
                if !valid_username(text) {
                    return Err(fail(7, "Invalid device identifier"));
                }
                *slot = Some(text.to_owned());
            }
        }
        if identifiers.iter().all(Option::is_none) {
            return Err(fail(7, "A Device Credential requires at least one field"));
        }
        let unique = unique_part(&identifiers);
        if unique.iter().all(|f| f.is_none()) {
            return Err(fail(
                7,
                "A Device Credential requires a serial, network, machine or media identifier",
            ));
        }
        let principal = super::system::certificate_principal(owner).unwrap_or(owner);
        let taken_by_policy = self
            .policy_devices
            .get(principal)
            .into_iter()
            .flatten()
            .any(|d| unique_part(&policy_identifiers(d)) == unique);
        let (taken, _) = self.store.locate(&system_owner(owner), 0, 0, |o| {
            device_material(o).is_some_and(|ids| unique_part(&ids) == unique)
        })?;
        if taken_by_policy || taken > 0 {
            return Err(fail(7, "Device identifiers are not unique"));
        }
        Ok(serde_json::to_vec(&DeviceMaterial { identifiers }).map_err(anyhow::Error::from)?)
    }
    /// A Password Link of a Device Credential must name a Password Credential
    /// of this principal (section 4.35.11), never a Secret Data object,
    /// which would hold the plaintext.
    pub(super) fn device_password_link(&self, owner: &str, a: &Node) -> R<Node> {
        let target = match &a.value {
            Value::Reference(id) if !id.is_empty() => id,
            Value::NameReference(_) => {
                return Err(fail(8, "Password Link name references are not supported"));
            }
            _ => return Err(fail(0x2d, "Invalid Password Link")),
        };
        let credential = self
            .store
            .get(&system_owner(owner), target)?
            .filter(|o| o.object_type == PASSWORD_CREDENTIAL_OBJECT)
            .ok_or(fail(
                0x2d,
                "Password Link target is not a Password Credential",
            ))?;
        Ok(Node::reference(PASSWORD_LINK, &credential.id))
    }
    /// Whether the principal has any device a Device credential could name.
    pub(super) fn has_devices(&self, owner: &str, v: Version) -> R<bool> {
        if self
            .policy_devices
            .get(owner)
            .is_some_and(|d| !d.is_empty())
        {
            return Ok(true);
        }
        if v.0 < 3 {
            return Ok(false);
        }
        let (count, _) = self.store.locate(&system_owner(owner), 0, 0, |o| {
            o.object_type == DEVICE_CREDENTIAL_OBJECT
        })?;
        Ok(count > 0)
    }
    /// The draft 3.0 Device Credential whose identifiers all equal the
    /// presented ones, with the verifier of its linked Password Credential
    /// (None when that credential was obliterated). The device is named by
    /// its Unique Identifier.
    pub(super) fn system_device(
        &self,
        owner: &str,
        presented: &[Option<&str>; 5],
    ) -> R<Option<(String, Option<PasswordVerifier>)>> {
        let system = system_owner(owner);
        let (_, found) = self.store.locate(&system, 0, 1, |o| {
            device_material(o).is_some_and(|ids| {
                ids.iter()
                    .zip(presented)
                    .all(|(stored, presented)| stored.as_deref() == *presented)
            })
        })?;
        let Some(device) = found.first() else {
            return Ok(None);
        };
        let Some(device) = self.store.get(&system, device)? else {
            return Ok(None);
        };
        let verifier = match password_link(&device) {
            Some(target) => self
                .store
                .get(&system, target)?
                .filter(|o| o.object_type == PASSWORD_CREDENTIAL_OBJECT)
                .map(|c| serde_json::from_slice(&c.material).map_err(|_| unreadable()))
                .transpose()?,
            None => None,
        };
        Ok(Some((device.id.clone(), verifier)))
    }
    /// Whether a device proved earlier is still a System Device Credential
    /// with its Password Credential.
    pub(super) fn system_device_current(&self, owner: &str, id: &str) -> R<bool> {
        let system = system_owner(owner);
        let Some(device) = self
            .store
            .get(&system, id)?
            .filter(|o| o.object_type == DEVICE_CREDENTIAL_OBJECT)
        else {
            return Ok(false);
        };
        Ok(match password_link(&device) {
            Some(target) => self
                .store
                .get(&system, target)?
                .is_some_and(|o| o.object_type == PASSWORD_CREDENTIAL_OBJECT),
            None => false,
        })
    }
    /// Startup check for `add_policy_devices`: a provisioned device never
    /// shares a name (the identity that owns objects) or identifiers with a
    /// System Device Credential, so each device has one source.
    pub(super) fn conflicts_with_system_device(
        &self,
        owner: &str,
        device: &PolicyDevice,
    ) -> anyhow::Result<bool> {
        let ids = policy_identifiers(device);
        let unique = unique_part(&ids);
        let (count, _) = self.store.locate(&system_owner(owner), 0, 0, |o| {
            device_material(o).is_some_and(|stored| unique_part(&stored) == unique)
                || o.object_type == DEVICE_CREDENTIAL_OBJECT && o.id == device.name
        })?;
        Ok(count > 0)
    }
    /// The System User of this name and the credentials it links.
    pub(super) fn system_user_credentials(
        &self,
        owner: &str,
        username: &str,
    ) -> R<Option<UserCredentials>> {
        let system = system_owner(owner);
        let (_, users) = self.store.locate(&system, 0, 1, |o| {
            o.object_type == USER && name_of(o) == Some(username)
        })?;
        let Some(user) = users.first() else {
            return Ok(None);
        };
        let Some(user) = self.store.get(&system, user)? else {
            return Ok(None);
        };
        let mut found = UserCredentials::default();
        for link in user.attrs.iter().filter(|a| a.tag == CREDENTIAL_LINK) {
            let Ok(target) = link.identifier_text() else {
                continue;
            };
            let Some(credential) = self.store.get(&system, target)? else {
                continue;
            };
            let id = credential.id.clone();
            let material = &credential.material;
            match credential.object_type {
                PASSWORD_CREDENTIAL_OBJECT if found.password.is_none() => {
                    let verifier = serde_json::from_slice(material).map_err(|_| unreadable())?;
                    found.password = Some((id, verifier));
                }
                OTP_CREDENTIAL_OBJECT if found.otp.is_none() => {
                    let otp: OtpMaterial =
                        serde_json::from_slice(material).map_err(|_| unreadable())?;
                    found.otp = Some((id, otp.totp));
                }
                HASHED_PASSWORD_CREDENTIAL_OBJECT if found.hashed.is_none() => {
                    let secret = serde_json::from_slice(material).map_err(|_| unreadable())?;
                    found.hashed = Some((id, secret));
                }
                _ => {}
            }
        }
        Ok(Some(found))
    }
    /// The identifiers of the existing credentials a System User links.
    pub(super) fn user_links(&self, owner: &str, username: &str) -> R<Vec<String>> {
        let system = system_owner(owner);
        let (_, users) = self.store.locate(&system, 0, 1, |o| {
            o.object_type == USER && name_of(o) == Some(username)
        })?;
        let mut links = vec![];
        for id in users {
            let Some(user) = self.store.get(&system, &id)? else {
                continue;
            };
            for link in user.attrs.iter().filter(|a| a.tag == CREDENTIAL_LINK) {
                if let Ok(target) = link.identifier_text()
                    && self.store.get(&system, target)?.is_some()
                {
                    links.push(target.to_owned());
                }
            }
        }
        Ok(links)
    }
}
