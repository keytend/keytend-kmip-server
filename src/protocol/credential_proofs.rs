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

//! KMIP 2.0+ Hashed Password and One Time Password request-header
//! credentials, verified against users-file users and, in draft 3.0, against
//! the Hashed Password, One Time Password and Password Credentials a System
//! User links (see docs/credentials.md and
//! docs/kmip-3.0.md#system-objects). A username has one source: a users-file
//! user is never looked up among System Users.
//!
//! Both keep the properties of the Username and Password path: every attempt
//! costs exactly one verifier derivation whether or not the user exists, every
//! failure is Authentication Not Successful, and no presented secret is kept.
//! A credential that verifies is single-use: its Timestamp or time step must
//! exceed the last one accepted for the user, a counter that is persisted
//! before the request runs (`Store::advance_replay_counter`).
use super::*;
use crate::credentials::{
    HashName, HashedPasswordSecret, MAX_PASSWORD_BYTES, PasswordVerifier, PolicyUser, TotpSecret,
    valid_username,
};

/// What one One Time Password attempt checks: the System credential that
/// proves the user (None for a users-file user), the password verifier and
/// the TOTP seed.
type OtpUser = (Option<String>, PasswordVerifier, TotpSecret);

/// Credential Type values (2.0 table 404, 2.1 table "Credential Type
/// Enumeration").
pub(super) const ONE_TIME_PASSWORD_TYPE: u32 = 4;
pub(super) const HASHED_PASSWORD_TYPE: u32 = 5;
/// Accepted distance between a Hashed Password Timestamp and the server
/// clock, either way. It bounds how long a credential that was captured but
/// never used stays usable.
pub const HASHED_PASSWORD_SKEW_MICROS: i64 = 300_000_000;

fn auth_failed() -> Failure {
    fail(3, "Authentication not successful")
}
fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as i64)
}
/// Opaque replay-counter key: no username reaches the database.
fn counter(kind: &[u8], owner: &str, user: &str) -> [u8; 32] {
    crypto::sha256_parts(&[
        b"keytend-kmip-server credential replay v1\0",
        kind,
        b"\0",
        owner.as_bytes(),
        b"\0",
        user.as_bytes(),
    ])
}

/// The Hashed Password fields that drive verification, read without
/// failing so that `credential_work` can use them too.
struct Hashed<'a> {
    username: &'a str,
    timestamp: i64,
    algorithm: u32,
    value: &'a [u8],
}
fn hashed_fields(value: &Node) -> R<Hashed<'_>> {
    no_fields(
        value,
        &[USERNAME, TIME_STAMP, HASHING_ALGORITHM, HASHED_PASSWORD],
    )?;
    let username = value.required(USERNAME)?.string()?;
    // 2.0/2.1 table "Credential Value Structure for the Hashed Password
    // Credential": Timestamp is a Date Time Extended (tag Time Stamp; the
    // tag table has no other timestamp tag).
    let timestamp = match value.required(TIME_STAMP)?.value {
        crate::ttlv::Value::DateTimeExtended(t) => t,
        _ => {
            return Err(fail(
                7,
                "Hashed Password Timestamp must be a Date Time Extended",
            ));
        }
    };
    // 2.0/2.1: "The Hashing Algorithm SHALL default to SHA 256."
    let algorithm = value
        .get(HASHING_ALGORITHM)
        .map(Node::number)
        .transpose()?
        .unwrap_or(HashName::Sha256.value());
    let value = value.required(HASHED_PASSWORD)?.byte_string()?;
    Ok(Hashed {
        username,
        timestamp,
        algorithm,
        value,
    })
}
/// The S2 half of a presented Hashed Password, when its length suits the
/// user's configured algorithm, and the bytes evaluated otherwise.
fn s2_of<'a>(secret: Option<&HashedPasswordSecret>, h: &Hashed<'a>) -> Option<&'a [u8]> {
    let secret = secret?;
    let len = secret.hashing_algorithm.output_len();
    (h.algorithm == secret.hashing_algorithm.value() && h.value.len() == 2 * len)
        .then(|| &h.value[len..])
}
fn burn_input<'a>(h: &Hashed<'a>) -> &'a [u8] {
    &h.value[..h.value.len().min(MAX_PASSWORD_BYTES)]
}

/// One Time Password fields (2.0/2.1 table "Credential Value Structure for
/// the One Time Password Credential").
struct Otp<'a> {
    username: &'a str,
    password: &'a [u8],
    code: &'a str,
}
fn otp_fields(value: &Node) -> R<Otp<'_>> {
    no_fields(value, &[USERNAME, PASSWORD, ONE_TIME_PASSWORD])?;
    Ok(Otp {
        username: value.required(USERNAME)?.string()?,
        // The table makes Password optional. A six-digit code alone is one
        // guess in a million per attempt with no rate limit, so the server
        // requires the Password as well; without it the credential fails.
        password: value
            .get(PASSWORD)
            .map(Node::string)
            .transpose()?
            .unwrap_or_default()
            .as_bytes(),
        code: value.required(ONE_TIME_PASSWORD)?.string()?,
    })
}

impl Engine {
    fn file_user(&self, owner: &str, username: &str) -> Option<&PolicyUser> {
        self.policy_users
            .get(owner)?
            .iter()
            .find(|u| u.username == username)
    }
    /// The Hashed Password material of a users-file user, or in draft 3.0
    /// of the Hashed Password Credential a System User links, with that
    /// credential's identifier.
    fn hashed_user(
        &self,
        owner: &str,
        v: Version,
        username: &str,
    ) -> R<Option<(Option<String>, HashedPasswordSecret)>> {
        if let Some(user) = self.file_user(owner, username) {
            return Ok(user.hashed_password.clone().map(|s| (None, s)));
        }
        if v.0 < 3 {
            return Ok(None);
        }
        Ok(self
            .system_user_credentials(owner, username)?
            .and_then(|c| c.hashed)
            .map(|(id, secret)| (Some(id), secret)))
    }
    /// The One Time Password material of a users-file user, or in draft 3.0
    /// of a System User linking both a One Time Password Credential and a
    /// Password Credential (the Password is required, see `otp_fields`).
    fn otp_user(&self, owner: &str, v: Version, username: &str) -> R<Option<OtpUser>> {
        if let Some(user) = self.file_user(owner, username) {
            return Ok(user
                .one_time_password
                .clone()
                .map(|totp| (None, user.password_scrypt.clone(), totp)));
        }
        if v.0 < 3 {
            return Ok(None);
        }
        Ok(self
            .system_user_credentials(owner, username)?
            .and_then(|c| Some((c.otp?, c.password?)))
            .map(|((id, totp), (_, password))| (Some(id), password, totp)))
    }
    /// Mirrors `verify_hashed_password` and `verify_one_time_password` for
    /// `credential_work`: the one verifier input each will evaluate.
    pub(super) fn proof_work(
        &self,
        owner: &str,
        v: Version,
        kind: u32,
        value: &Node,
        work: &mut crate::credentials::Work,
    ) {
        match kind {
            HASHED_PASSWORD_TYPE => {
                let Ok(h) = hashed_fields(value) else { return };
                let found = valid_username(h.username)
                    .then(|| self.hashed_user(owner, v, h.username).ok().flatten())
                    .flatten();
                let secret = found.as_ref().map(|(_, s)| s);
                match (secret, s2_of(secret, &h)) {
                    (Some(secret), Some(s2)) => work.verify(&secret.s2_scrypt, s2),
                    _ if self.has_users(owner).unwrap_or(false) => work.burn(burn_input(&h)),
                    _ => {}
                }
            }
            ONE_TIME_PASSWORD_TYPE => {
                let Ok(o) = otp_fields(value) else { return };
                if o.password.is_empty() || o.password.len() > MAX_PASSWORD_BYTES {
                    return;
                }
                let found = valid_username(o.username)
                    .then(|| self.otp_user(owner, v, o.username).ok().flatten())
                    .flatten();
                match found {
                    Some((_, password, _)) => work.verify(&password, o.password),
                    None if self.has_users(owner).unwrap_or(false) => work.burn(o.password),
                    None => {}
                }
            }
            _ => {}
        }
    }

    /// KMIP 2.0+ Hashed Password credential. Returns the username, the
    /// System credential that proved it (None: users file) and the response
    /// header Server Hashed Password.
    ///
    /// 2.0/2.1: "The timestamp is the current timestamp used to produce the
    /// hash and SHALL monotonically increase", so a Timestamp at or below
    /// the user's last accepted one is a replay and fails.
    pub(super) fn verify_hashed_password(
        &mut self,
        owner: &str,
        v: Version,
        value: &Node,
    ) -> R<(String, Option<String>, Vec<u8>)> {
        let h = hashed_fields(value)?;
        let found = if valid_username(h.username) {
            self.hashed_user(owner, v, h.username)?
        } else {
            None
        };
        let (credential, secret) = found.unzip();
        let secret = secret.as_ref();
        let Some((secret, s2)) = secret.zip(s2_of(secret, &h)) else {
            if self.has_users(owner)? {
                PasswordVerifier::burn(burn_input(&h));
            }
            return Err(auth_failed());
        };
        // Both halves are always checked, so timing does not reveal which
        // one was wrong.
        let s2_ok = secret.s2_scrypt.verify(s2);
        let len = secret.hashing_algorithm.output_len();
        let first_ok = secret.first_half_matches(h.timestamp, &h.value[..len]);
        let fresh = (h.timestamp - now_micros()).abs() <= HASHED_PASSWORD_SKEW_MICROS;
        if !(s2_ok && first_ok && fresh) {
            return Err(auth_failed());
        }
        let proof = secret.server_proof(h.timestamp, s2);
        let username = h.username.to_owned();
        let key = counter(b"hashed-password", owner, &username);
        if !self.store.advance_replay_counter(&key, h.timestamp)? {
            return Err(auth_failed());
        }
        Ok((username, credential.flatten(), proof))
    }

    /// KMIP 2.0+ One Time Password credential: the Password must verify and
    /// the One Time Password must be the user's TOTP code (RFC 6238) for a
    /// time step within one step of the server clock that is later than
    /// the last step accepted for the user. 2.0/2.1: the OTP "may only be
    /// used for a single authentication"; RFC 6238 section 5.2 likewise
    /// forbids accepting an OTP a second time.
    pub(super) fn verify_one_time_password(
        &mut self,
        owner: &str,
        v: Version,
        value: &Node,
    ) -> R<(String, Option<String>)> {
        let o = otp_fields(value)?;
        let user = if valid_username(o.username)
            && !o.password.is_empty()
            && o.password.len() <= MAX_PASSWORD_BYTES
        {
            self.otp_user(owner, v, o.username)?
        } else {
            None
        };
        let Some((credential, password, totp)) = user else {
            if self.has_users(owner)? {
                PasswordVerifier::burn(o.password);
            }
            return Err(auth_failed());
        };
        let password_ok = password.verify(o.password);
        let step = totp.matching_step(o.code, now_micros().div_euclid(1_000_000));
        let (Some(step), true) = (step, password_ok) else {
            return Err(auth_failed());
        };
        let username = o.username.to_owned();
        let key = counter(b"one-time-password", owner, &username);
        // The counter holds the step's start time in seconds, so it stays
        // monotonic if the operator changes the interval.
        let start = step.saturating_mul(i64::from(totp.interval));
        if !self.store.advance_replay_counter(&key, start)? {
            return Err(auth_failed());
        }
        Ok((username, credential))
    }
}
