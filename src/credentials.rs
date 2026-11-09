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

//! Password verifiers for request-header credentials (KMIP 1.0+ Username and
//! Password, 1.1+ Device) and draft 3.0 password credentials. Passwords are never stored:
//! only a random salt and a PBKDF2-HMAC-SHA-256 output (NIST SP 800-132),
//! compared in constant time. Older verifiers hold scrypt outputs instead;
//! they keep verifying outside FIPS mode and never authenticate in FIPS mode
//! (docs/fips.md).
//!
//! The KMIP 2.0+ Hashed Password and One Time Password credentials need
//! material the server can recompute from (`HashedPasswordSecret`,
//! `TotpSecret`). Both are weaker than a salted verifier, so `serve` accepts
//! them only with an explicit opt-in; see docs/credentials.md.
use crate::fips::approved::MIN_PBKDF2_PASSWORD_BYTES;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Server-chosen cost for new verifiers: PBKDF2-HMAC-SHA-256 with 600 000
/// iterations. SP 800-132 section 5.2 asks for "as large as possible" a
/// count, at least 1000; 600 000 is the OWASP Password Storage Cheat Sheet
/// figure for PBKDF2-HMAC-SHA-256 and costs about as much CPU time per
/// verification as the scrypt parameters it replaces.
pub const PBKDF2_ITERATIONS: u32 = 600_000;
/// Legacy scrypt cost (N=2^15, r=8, p=1; 32 MiB), accepted only to verify.
const LOG_N: u8 = 15;
const R: u32 = 8;
const P: u32 = 1;
/// 128-bit salts: SP 800-132 section 5.1 requires at least 128 bits.
const SALT_BYTES: usize = 16;
const HASH_BYTES: usize = 32;
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// A stored password verifier. Every verifier the server creates is PBKDF2;
/// legacy scrypt verifiers are read and verified outside FIPS
/// mode. The JSON forms differ in their fields, so neither needs a tag.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PasswordVerifier {
    Pbkdf2(Pbkdf2Verifier),
    Scrypt(ScryptVerifier),
}
/// `{"algorithm": "PBKDF2-HMAC-SHA-256", "iterations": 600000, "salt": hex, "hash": hex}`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pbkdf2Verifier {
    pub algorithm: Pbkdf2Algorithm,
    pub iterations: u32,
    #[serde(with = "hex_bytes")]
    pub salt: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub hash: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Pbkdf2Algorithm {
    #[serde(rename = "PBKDF2-HMAC-SHA-256")]
    HmacSha256,
}
/// The older scrypt form: `{"log_n": 15, "r": 8, "p": 1, "salt": hex, "hash": hex}`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScryptVerifier {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    #[serde(with = "hex_bytes")]
    pub salt: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub hash: Vec<u8>,
}
impl std::fmt::Debug for PasswordVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordVerifier")
            .field("kdf", &self.kdf())
            .finish_non_exhaustive()
    }
}
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
/// The derivation of one verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kdf {
    Pbkdf2 { iterations: u32 },
    Scrypt { log_n: u8, r: u32, p: u32 },
}
const SERVER_KDF: Kdf = Kdf::Pbkdf2 {
    iterations: PBKDF2_ITERATIONS,
};
thread_local! {
    /// Verifier derivations performed on this thread (see `derivations`).
    static DERIVATIONS: Cell<u64> = const { Cell::new(0) };
    /// Outputs computed before the engine lock was taken (`Derivations`).
    static PRECOMPUTED: RefCell<HashMap<[u8; 32], Zeroizing<Vec<u8>>>> =
        RefCell::new(HashMap::new());
}
/// The number of verifier derivations this thread has performed.
/// Verification that uses a `Derivations` result does not count.
pub fn derivations() -> u64 {
    DERIVATIONS.with(Cell::get)
}
/// Identifies one derivation input without keeping the password: SHA-256
/// over the parameters, salt and password.
fn input_digest(password: &[u8], salt: &[u8], kdf: Kdf) -> [u8; 32] {
    let parameters = match kdf {
        Kdf::Pbkdf2 { iterations } => {
            [&b"pbkdf2-hmac-sha256"[..], &iterations.to_be_bytes()].concat()
        }
        Kdf::Scrypt { log_n, r, p } => [&[log_n][..], &r.to_be_bytes(), &p.to_be_bytes()].concat(),
    };
    crate::crypto::sha256_parts(&[
        &parameters,
        &(salt.len() as u64).to_be_bytes(),
        salt,
        password,
    ])
}
fn compute(password: &[u8], salt: &[u8], kdf: Kdf) -> Result<Zeroizing<Vec<u8>>> {
    DERIVATIONS.with(|d| d.set(d.get() + 1));
    let mut out = Zeroizing::new(vec![0; HASH_BYTES]);
    match kdf {
        Kdf::Pbkdf2 { iterations } => openssl::pkcs5::pbkdf2_hmac(
            password,
            salt,
            iterations as usize,
            openssl::hash::MessageDigest::sha256(),
            &mut out,
        )?,
        Kdf::Scrypt { log_n, r, p } => {
            crate::fips::refuse("scrypt")?;
            let n = 1u64 << log_n;
            // 128 * r * (N + p) bytes plus slack, as OpenSSL's EVP_PBE_scrypt requires.
            let maxmem = 128 * u64::from(r) * (n + u64::from(p) + 2);
            openssl::pkcs5::scrypt(password, salt, n, r.into(), p.into(), maxmem, &mut out)?;
        }
    }
    Ok(out)
}
fn derive(password: &[u8], salt: &[u8], kdf: Kdf) -> Result<Zeroizing<Vec<u8>>> {
    let key = input_digest(password, salt, kdf);
    if let Some(out) = PRECOMPUTED.with(|m| m.borrow().get(&key).cloned()) {
        return Ok(out);
    }
    compute(password, salt, kdf)
}
fn burn_input(password: &[u8]) -> Vec<u8> {
    let mut input = password[..password.len().min(MAX_PASSWORD_BYTES)].to_vec();
    // The burn costs a full derivation in FIPS mode too, where the provider
    // refuses shorter PBKDF2 passwords at once.
    input.resize(input.len().max(MIN_PBKDF2_PASSWORD_BYTES), 0);
    input
}
/// FIPS mode refuses PBKDF2 passwords shorter than the RHEL 9 provider's
/// minimum, whichever provider is loaded (docs/fips.md), so a short password
/// never authenticates there.
fn fips_short(password: &[u8]) -> bool {
    crate::fips::active() && password.len() < MIN_PBKDF2_PASSWORD_BYTES
}

/// Derivation inputs a request's credentials will need, collected while the
/// engine is locked (`Engine::credential_work`) so that the costly
/// evaluations can run before the lock is taken again.
#[derive(Default)]
pub struct Work(Vec<Input>);
/// Password, salt and derivation of one evaluation.
type Input = (Zeroizing<Vec<u8>>, Vec<u8>, Kdf);
impl Work {
    pub(crate) fn verify(&mut self, verifier: &PasswordVerifier, password: &[u8]) {
        if verifier.validate().is_err() || password.len() > MAX_PASSWORD_BYTES {
            return;
        }
        // FIPS mode spends one burn on a scrypt verifier or a short password
        // (`verify`).
        if verifier.kdf() != SERVER_KDF && crate::fips::active() || fips_short(password) {
            return self.burn(password);
        }
        self.0.push((
            Zeroizing::new(password.to_vec()),
            verifier.salt().to_vec(),
            verifier.kdf(),
        ));
    }
    pub(crate) fn burn(&mut self, password: &[u8]) {
        self.0.push((
            Zeroizing::new(burn_input(password)),
            vec![0; SALT_BYTES],
            SERVER_KDF,
        ));
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Evaluate every input; call without holding the engine lock. At most
    /// `PARALLEL` evaluations run at once across the process.
    pub fn run(self) -> Derivations {
        let mut out = HashMap::new();
        for (password, salt, kdf) in self.0 {
            let _slot = Slot::acquire();
            if let Ok(value) = compute(&password, &salt, kdf) {
                out.insert(input_digest(&password, &salt, kdf), value);
            }
        }
        Derivations(out)
    }
}
/// Concurrent unlocked derivations allowed process-wide.
const PARALLEL: usize = 4;
static SLOTS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
static SLOT_FREED: std::sync::Condvar = std::sync::Condvar::new();
struct Slot;
impl Slot {
    fn acquire() -> Self {
        let mut used = SLOTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *used >= PARALLEL {
            used = SLOT_FREED
                .wait(used)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *used += 1;
        Slot
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        let mut used = SLOTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *used -= 1;
        SLOT_FREED.notify_one();
    }
}
/// Precomputed verifier outputs, used by verification on this thread inside
/// `Derivations::scope`. A verifier that changed in between simply misses and
/// is evaluated again, so the results never decide anything on their own.
#[derive(Default)]
pub struct Derivations(HashMap<[u8; 32], Zeroizing<Vec<u8>>>);
impl Derivations {
    pub fn scope<T>(self, f: impl FnOnce() -> T) -> T {
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                PRECOMPUTED.with(|m| m.borrow_mut().clear());
            }
        }
        PRECOMPUTED.with(|m| *m.borrow_mut() = self.0);
        let _clear = Clear;
        f()
    }
}
impl PasswordVerifier {
    /// A new PBKDF2-HMAC-SHA-256 verifier with a fresh 128-bit salt from the
    /// provider DRBG.
    pub fn new(password: &[u8]) -> Result<Self> {
        if password.is_empty() || password.len() > MAX_PASSWORD_BYTES || fips_short(password) {
            bail!("password length is outside the accepted range");
        }
        let salt = crate::crypto::random(SALT_BYTES)?.to_vec();
        let hash = derive(password, &salt, SERVER_KDF)?.to_vec();
        Ok(Self::Pbkdf2(Pbkdf2Verifier {
            algorithm: Pbkdf2Algorithm::HmacSha256,
            iterations: PBKDF2_ITERATIONS,
            salt,
            hash,
        }))
    }
    pub fn kdf(&self) -> Kdf {
        match self {
            Self::Pbkdf2(v) => Kdf::Pbkdf2 {
                iterations: v.iterations,
            },
            Self::Scrypt(v) => Kdf::Scrypt {
                log_n: v.log_n,
                r: v.r,
                p: v.p,
            },
        }
    }
    pub fn salt(&self) -> &[u8] {
        match self {
            Self::Pbkdf2(v) => &v.salt,
            Self::Scrypt(v) => &v.salt,
        }
    }
    fn hash(&self) -> &[u8] {
        match self {
            Self::Pbkdf2(v) => &v.hash,
            Self::Scrypt(v) => &v.hash,
        }
    }
    /// A legacy scrypt verifier: it cannot authenticate in
    /// FIPS mode and should be re-provisioned.
    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::Scrypt(_))
    }
    /// Every verifier uses the server's parameters for its derivation, so
    /// each check of a known or unknown username costs the same (`burn`) and
    /// response time does not reveal which usernames exist. Legacy scrypt
    /// verifiers keep their own fixed cost, which is close to it.
    pub fn validate(&self) -> Result<()> {
        let salt = self.salt().len();
        if self.kdf() != SERVER_KDF
            && self.kdf()
                != (Kdf::Scrypt {
                    log_n: LOG_N,
                    r: R,
                    p: P,
                })
            || !(SALT_BYTES..=64).contains(&salt)
            || self.hash().len() != HASH_BYTES
        {
            bail!("password verifier parameters are outside the accepted range");
        }
        Ok(())
    }
    pub fn verify(&self, password: &[u8]) -> bool {
        if self.validate().is_err() || password.len() > MAX_PASSWORD_BYTES {
            return false;
        }
        if self.is_legacy() && crate::fips::active() {
            // Fail closed at the cost of an unknown user's check.
            tracing::warn!(
                "a scrypt password verifier cannot authenticate in FIPS mode; re-provision it as PBKDF2 (keytend-kmip-server password-verifier)"
            );
            Self::burn(password);
            return false;
        }
        if fips_short(password) {
            Self::burn(password);
            return false;
        }
        derive(password, self.salt(), self.kdf())
            .is_ok_and(|candidate| bool::from(candidate.as_slice().ct_eq(self.hash())))
    }
    /// Spend the cost of one verification when no verifier exists, so an
    /// unknown username is not distinguishable by response time.
    pub fn burn(password: &[u8]) {
        let _ = derive(&burn_input(password), &[0; SALT_BYTES], SERVER_KDF);
    }
}

/// An operator-provisioned user bound to one certificate principal. The
/// policy carries only the verifier; the password never appears in it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyUser {
    pub username: String,
    /// Users-file key `password_verifier`; `password_scrypt` is the older name.
    #[serde(rename = "password_verifier", alias = "password_scrypt")]
    pub password_scrypt: PasswordVerifier,
    /// Only administrators may create or obliterate draft 3.0 System
    /// Objects (users, groups and credentials). Off unless set.
    #[serde(default)]
    pub administrator: bool,
    /// KMIP 2.0+ Hashed Password credential material (opt-in).
    #[serde(default)]
    pub hashed_password: Option<HashedPasswordSecret>,
    /// KMIP 2.0+ One Time Password credential seed (opt-in, TOTP).
    #[serde(default)]
    pub one_time_password: Option<TotpSecret>,
}
impl PolicyUser {
    /// Whether the entry holds recomputable secrets that `serve` accepts
    /// only with `--allow-stored-credential-secrets`.
    pub fn stores_secrets(&self) -> bool {
        self.hashed_password.is_some() || self.one_time_password.is_some()
    }
}

/// Hashing Algorithm values (2.0 and 2.1 Hashing Algorithm Enumeration)
/// accepted for the Hashed Password and Server Hashed Password: SHA-2 only.
/// MD5 and SHA-1 are refused at startup.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashName {
    #[serde(rename = "SHA-256")]
    Sha256,
    #[serde(rename = "SHA-384")]
    Sha384,
    #[serde(rename = "SHA-512")]
    Sha512,
}
impl HashName {
    /// The Hashing Algorithm enumeration value.
    pub fn value(self) -> u32 {
        match self {
            Self::Sha256 => 6,
            Self::Sha384 => 7,
            Self::Sha512 => 8,
        }
    }
    pub fn output_len(self) -> usize {
        self.digest().size()
    }
    fn digest(self) -> openssl::hash::MessageDigest {
        match self {
            Self::Sha256 => openssl::hash::MessageDigest::sha256(),
            Self::Sha384 => openssl::hash::MessageDigest::sha384(),
            Self::Sha512 => openssl::hash::MessageDigest::sha512(),
        }
    }
    pub fn hash(self, parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
        let mut h = openssl::hash::Hasher::new(self.digest()).expect("digest");
        for part in parts {
            h.update(part).expect("digest");
        }
        Zeroizing::new(h.finish().expect("digest").to_vec())
    }
}
fn default_hash() -> HashName {
    HashName::Sha256
}

/// What the server needs to check a Hashed Password credential (2.0/2.1
/// table "Credential Value Structure for the Hashed Password Credential"):
/// Hashed Password = Hash(S1 || Timestamp) || S2, S1 = Hash(Username ||
/// Password), S2 = Hash(Password || Username).
///
/// The server must recompute Hash(S1 || Timestamp), so S1 is stored as is.
/// S1 alone does not authenticate: the S2 half is checked against a salted
/// password verifier. S1 is, however, an unsalted fast hash of the password, so
/// a leaked users file lets the password be guessed at SHA-2 speed.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HashedPasswordSecret {
    /// The algorithm the client must use; "The Hashing Algorithm SHALL
    /// default to SHA 256".
    #[serde(default = "default_hash")]
    pub hashing_algorithm: HashName,
    #[serde(with = "hex_bytes")]
    pub s1: Vec<u8>,
    /// Key `s2_verifier`; `s2_scrypt` is the older name.
    #[serde(rename = "s2_verifier", alias = "s2_scrypt")]
    pub s2_scrypt: PasswordVerifier,
}
impl std::fmt::Debug for HashedPasswordSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashedPasswordSecret")
            .field("hashing_algorithm", &self.hashing_algorithm)
            .finish_non_exhaustive()
    }
}
/// S1 and S2 of one username and password. Usernames and passwords are
/// hashed as their UTF-8 bytes, the Text String value encoding.
pub fn hashed_password_parts(
    algorithm: HashName,
    username: &str,
    password: &str,
) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let (u, p) = (username.as_bytes(), password.as_bytes());
    (algorithm.hash(&[u, p]), algorithm.hash(&[p, u]))
}
/// The Timestamp as hashed: its 8-byte big-endian Date Time Extended value
/// encoding (2.1 section 10.1.4).
pub fn timestamp_bytes(microseconds: i64) -> [u8; 8] {
    microseconds.to_be_bytes()
}
impl HashedPasswordSecret {
    pub fn new(algorithm: HashName, username: &str, password: &str) -> Result<Self> {
        let (s1, s2) = hashed_password_parts(algorithm, username, password);
        Ok(Self {
            hashing_algorithm: algorithm,
            s1: s1.to_vec(),
            s2_scrypt: PasswordVerifier::new(&s2)?,
        })
    }
    pub fn validate(&self) -> Result<()> {
        if self.s1.len() != self.hashing_algorithm.output_len() {
            bail!("hashed password S1 does not match its hashing algorithm");
        }
        self.s2_scrypt.validate()
    }
    /// Whether the first half equals Hash(S1 || Timestamp), in constant time.
    /// The S2 half is checked separately against `s2_scrypt`.
    pub fn first_half_matches(&self, timestamp: i64, presented: &[u8]) -> bool {
        let expected = self
            .hashing_algorithm
            .hash(&[&self.s1, &timestamp_bytes(timestamp)]);
        bool::from(expected.as_slice().ct_eq(presented))
    }
    /// Response header Server Hashed Password (2.0/2.1 table "Response
    /// Header Structure"): Hash(Timestamp || S1 || Hash(S2)).
    pub fn server_proof(&self, timestamp: i64, s2: &[u8]) -> Vec<u8> {
        let algorithm = self.hashing_algorithm;
        let s2 = algorithm.hash(&[s2]);
        algorithm
            .hash(&[&timestamp_bytes(timestamp), &self.s1, &s2])
            .to_vec()
    }
}

/// HMAC functions for TOTP (RFC 6238 section 1.2: SHA-1, SHA-256, SHA-512).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TotpDigest {
    #[serde(rename = "SHA-1")]
    Sha1,
    #[serde(rename = "SHA-256")]
    Sha256,
    #[serde(rename = "SHA-512")]
    Sha512,
}
fn default_totp_digest() -> TotpDigest {
    TotpDigest::Sha1
}
fn default_digits() -> u32 {
    6
}
fn default_interval() -> u32 {
    30
}
/// A One Time Password seed. KMIP 2.0/2.1 do not name an algorithm; the
/// server uses TOTP (RFC 6238), which draft 3.0 enumerates as an OTP
/// Algorithm next to HOTP. HOTP is not offered: its counter could not be
/// trusted after a restore. The seed is a shared secret: whoever reads it
/// can produce codes, which is why the Password is also required.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TotpSecret {
    #[serde(with = "hex_bytes")]
    pub seed: Vec<u8>,
    #[serde(default = "default_totp_digest")]
    pub digest: TotpDigest,
    #[serde(default = "default_digits")]
    pub digits: u32,
    /// Time step X in seconds (RFC 6238 section 4.1).
    #[serde(default = "default_interval")]
    pub interval: u32,
}
impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSecret")
            .field("digest", &self.digest)
            .field("digits", &self.digits)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}
/// Accepted clock drift in time steps either way (RFC 6238 section 5.2
/// recommends at most one step of network delay).
pub const TOTP_WINDOW: i64 = 1;
impl TotpSecret {
    pub fn validate(&self) -> Result<()> {
        // RFC 4226 R6: the shared secret is at least 128 bits.
        if self.seed.len() < 16
            || self.seed.len() > 64
            || !(6..=8).contains(&self.digits)
            || !(15..=300).contains(&self.interval)
        {
            bail!("one time password seed, digits or interval are outside the accepted range");
        }
        Ok(())
    }
    /// The time step containing `seconds` since the epoch.
    pub fn step(&self, seconds: i64) -> i64 {
        seconds.div_euclid(i64::from(self.interval))
    }
    /// The code for one time step (RFC 4226 section 5.3 with T as the
    /// counter, RFC 6238 section 4.2).
    pub fn code(&self, step: i64) -> Zeroizing<String> {
        use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
        let digest = match self.digest {
            TotpDigest::Sha1 => MessageDigest::sha1(),
            TotpDigest::Sha256 => MessageDigest::sha256(),
            TotpDigest::Sha512 => MessageDigest::sha512(),
        };
        let key = PKey::hmac(&self.seed).expect("hmac key");
        let mut signer = Signer::new(digest, &key).expect("hmac");
        let mac = Zeroizing::new(
            signer
                .sign_oneshot_to_vec(&step.to_be_bytes())
                .expect("hmac"),
        );
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let binary =
            u32::from_be_bytes(mac[offset..offset + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;
        let code = binary % 10u32.pow(self.digits);
        Zeroizing::new(format!("{code:0width$}", width = self.digits as usize))
    }
    /// The newest time step within the window whose code equals `presented`.
    /// Every candidate is computed and compared in constant time.
    pub fn matching_step(&self, presented: &str, seconds: i64) -> Option<i64> {
        let now = self.step(seconds);
        let mut found = None;
        for step in now - TOTP_WINDOW..=now + TOTP_WINDOW {
            if bool::from(self.code(step).as_bytes().ct_eq(presented.as_bytes())) {
                found = Some(step);
            }
        }
        found
    }
}
pub fn valid_username(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control)
}
pub fn validate_users(users: &[PolicyUser]) -> Result<()> {
    if users.len() > 64 {
        bail!("at most 64 policy users are permitted per certificate");
    }
    let mut names = std::collections::HashSet::new();
    for user in users {
        if !valid_username(&user.username) || !names.insert(user.username.as_str()) {
            bail!("invalid or duplicate policy username");
        }
        user.password_scrypt.validate()?;
        if let Some(secret) = &user.hashed_password {
            secret.validate()?;
        }
        if let Some(secret) = &user.one_time_password {
            secret.validate()?;
        }
    }
    Ok(())
}

/// An operator-provisioned device of one certificate principal (KMIP 1.1+
/// Device credential). A request matches it only when every identifier it
/// carries equals the configured one and no other is present, and its password
/// verifies: identifiers are not secrets, so the password is mandatory here.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDevice {
    /// Names the device in audit records.
    pub name: String,
    #[serde(default)]
    pub device_serial_number: Option<String>,
    #[serde(default)]
    pub device_identifier: Option<String>,
    #[serde(default)]
    pub network_identifier: Option<String>,
    #[serde(default)]
    pub machine_identifier: Option<String>,
    #[serde(default)]
    pub media_identifier: Option<String>,
    #[serde(rename = "password_verifier", alias = "password_scrypt")]
    pub password_scrypt: PasswordVerifier,
}
impl PolicyDevice {
    /// "One or a combination of the Device Serial Number, Network Identifier,
    /// Machine Identifier, and Media Identifier SHALL be unique" (1.1 section 2.1.2).
    fn unique_part(&self) -> [&Option<String>; 4] {
        [
            &self.device_serial_number,
            &self.network_identifier,
            &self.machine_identifier,
            &self.media_identifier,
        ]
    }
    pub fn identifiers(&self) -> [&Option<String>; 5] {
        [
            &self.device_serial_number,
            &self.device_identifier,
            &self.network_identifier,
            &self.machine_identifier,
            &self.media_identifier,
        ]
    }
}
pub fn validate_devices(devices: &[PolicyDevice]) -> Result<()> {
    if devices.len() > 64 {
        bail!("at most 64 policy devices are permitted per certificate");
    }
    let mut names = std::collections::HashSet::new();
    let mut identities = std::collections::HashSet::new();
    for device in devices {
        if !valid_username(&device.name)
            || !names.insert(device.name.as_str())
            || device.unique_part().iter().all(|f| f.is_none())
            || !identities.insert(device.unique_part())
            || device
                .identifiers()
                .iter()
                .any(|f| f.as_deref().is_some_and(|f| !valid_username(f)))
        {
            bail!("invalid, unidentified or duplicate policy device");
        }
        device.password_scrypt.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A verifier in the legacy scrypt form.
    fn scrypt_verifier(password: &[u8]) -> PasswordVerifier {
        let salt = vec![7; SALT_BYTES];
        let mut hash = vec![0; HASH_BYTES];
        openssl::pkcs5::scrypt(
            password,
            &salt,
            1 << LOG_N,
            R.into(),
            P.into(),
            64 << 20,
            &mut hash,
        )
        .unwrap();
        PasswordVerifier::Scrypt(ScryptVerifier {
            log_n: LOG_N,
            r: R,
            p: P,
            salt,
            hash,
        })
    }
    #[test]
    fn verifiers_are_salted_and_check_only_the_right_password() {
        let a = PasswordVerifier::new(b"correct horse").unwrap();
        let b = PasswordVerifier::new(b"correct horse").unwrap();
        assert_ne!(a.salt(), b.salt());
        assert_ne!(a.hash(), b.hash());
        assert_eq!(a.salt().len(), 16);
        assert_eq!(
            a.kdf(),
            Kdf::Pbkdf2 {
                iterations: 600_000
            }
        );
        assert!(a.verify(b"correct horse"));
        assert!(!a.verify(b"correct horsf"));
        assert!(!a.verify(b""));
        assert!(PasswordVerifier::new(b"").is_err());
        assert!(PasswordVerifier::new(&[b'x'; MAX_PASSWORD_BYTES + 1]).is_err());
        let json = serde_json::to_string(&a).unwrap();
        assert!(!json.contains("correct"));
        assert!(
            json.contains("\"algorithm\":\"PBKDF2-HMAC-SHA-256\""),
            "{json}"
        );
        assert!(json.contains("\"iterations\":600000"), "{json}");
        assert_eq!(serde_json::from_str::<PasswordVerifier>(&json).unwrap(), a);
        assert!(!format!("{a:?}").contains(&hex::encode(a.hash())));
    }
    /// The verifier is PBKDF2-HMAC-SHA-256 as SP 800-132 and RFC 8018 define
    /// it: the hash below is Python's
    /// `hashlib.pbkdf2_hmac('sha256', b'password', bytes(range(16)), 600000)`.
    #[test]
    fn pbkdf2_verifier_matches_an_independent_computation() {
        let v: PasswordVerifier = serde_json::from_str(
            r#"{"algorithm":"PBKDF2-HMAC-SHA-256","iterations":600000,"salt":"000102030405060708090a0b0c0d0e0f","hash":"3bc37118e625093e9b79ed08930ea7af7389591233fdd92dddf369371e60dbc0"}"#,
        )
        .unwrap();
        v.validate().unwrap();
        assert!(v.verify(b"password"));
        assert!(!v.verify(b"Password"));
        // FIPS mode verifies PBKDF2 verifiers unchanged.
        crate::fips::scope(true, || assert!(v.verify(b"password")));
    }
    #[test]
    fn legacy_scrypt_verifiers_verify_outside_fips_mode_only() {
        let legacy = scrypt_verifier(b"pw");
        assert!(legacy.is_legacy());
        legacy.validate().unwrap();
        // The legacy users-file and stored form still parses.
        let json = serde_json::to_string(&legacy).unwrap();
        assert!(json.contains("\"log_n\":15"), "{json}");
        assert_eq!(
            serde_json::from_str::<PasswordVerifier>(&json).unwrap(),
            legacy
        );
        assert!(legacy.verify(b"pw"));
        assert!(!legacy.verify(b"px"));
        let fresh = PasswordVerifier::new(b"pw").unwrap();
        assert!(!fresh.is_legacy());
        crate::fips::scope(true, || {
            // Fails closed, at the cost of one PBKDF2 burn.
            let before = derivations();
            assert!(!legacy.verify(b"pw"));
            assert_eq!(derivations(), before + 1);
            assert!(compute(b"pw", &[7; 16], legacy.kdf()).is_err());
            // A precomputed scrypt output does not get around it either.
            let mut work = Work::default();
            work.verify(&legacy, b"pw");
            assert_eq!(work.0.len(), 1);
            assert_eq!(work.0[0].2, SERVER_KDF);
            // "pw" is shorter than FIPS mode's PBKDF2 password minimum.
            assert!(!fresh.verify(b"pw"));
        });
    }
    #[test]
    fn fips_mode_refuses_pbkdf2_passwords_below_eight_bytes() {
        let short = PasswordVerifier::new(b"1234567").unwrap();
        let long = PasswordVerifier::new(b"12345678").unwrap();
        assert!(short.verify(b"1234567") && long.verify(b"12345678"));
        crate::fips::scope(true, || {
            // Refused without asking the provider, at the cost of one burn,
            // like an unknown user.
            let before = derivations();
            assert!(!short.verify(b"1234567"));
            assert_eq!(derivations(), before + 1);
            assert!(long.verify(b"12345678"));
            assert!(PasswordVerifier::new(b"1234567").is_err());
            let mut work = Work::default();
            work.verify(&short, b"1234567");
            assert_eq!(work.0.len(), 1);
            assert_eq!(work.0[0].0.len(), MIN_PBKDF2_PASSWORD_BYTES);
            assert_eq!(work.0[0].1, vec![0; SALT_BYTES]);
        });
        // The burn input of a short password is padded in both modes; its
        // output is never compared.
        assert_eq!(burn_input(b"").len(), MIN_PBKDF2_PASSWORD_BYTES);
        assert_eq!(burn_input(b"123456789").len(), 9);
    }
    #[test]
    fn precomputed_derivations_replace_evaluation_inside_the_scope_only() {
        let v = PasswordVerifier::new(b"pw").unwrap();
        let mut work = Work::default();
        work.verify(&v, b"pw");
        work.verify(&v, b"wrong");
        work.burn(b"other");
        let done = work.run();
        let before = derivations();
        done.scope(|| {
            assert!(v.verify(b"pw"));
            assert!(!v.verify(b"wrong"));
            PasswordVerifier::burn(b"other");
        });
        assert_eq!(derivations(), before);
        // Outside the scope, or for inputs not prepared, PBKDF2 runs again.
        assert!(v.verify(b"pw"));
        Derivations::default().scope(|| assert!(!v.verify(b"x")));
        assert_eq!(derivations(), before + 2);
    }
    // REQ:1a88f6341c702397 provisioned devices differ in serial, network, machine or media identifiers
    #[test]
    fn weak_or_malformed_policy_verifiers_are_rejected() {
        let good = PasswordVerifier::new(b"pw").unwrap();
        let PasswordVerifier::Pbkdf2(pbkdf2) = good.clone() else {
            panic!("expected PBKDF2")
        };
        // Valid costs other than the server's are refused too, so
        // verification time does not depend on the user.
        for mutate in [
            (|v: &mut Pbkdf2Verifier| v.iterations = 1000) as fn(&mut Pbkdf2Verifier),
            |v| v.iterations = 600_001,
            |v| v.salt.truncate(8),
            |v| v.salt = vec![1; 65],
            |v| v.hash.truncate(16),
        ] {
            let mut bad = pbkdf2.clone();
            mutate(&mut bad);
            let bad = PasswordVerifier::Pbkdf2(bad);
            assert!(bad.validate().is_err());
            assert!(!bad.verify(b"pw"));
        }
        let PasswordVerifier::Scrypt(scrypt) = scrypt_verifier(b"pw") else {
            unreachable!()
        };
        for mutate in [
            (|v: &mut ScryptVerifier| v.log_n = 10) as fn(&mut ScryptVerifier),
            |v| v.log_n = 16,
            |v| v.r = 1,
            |v| v.p = 0,
            |v| v.p = 2,
            |v| v.salt.truncate(8),
            |v| v.hash.truncate(16),
        ] {
            let mut bad = scrypt.clone();
            mutate(&mut bad);
            let bad = PasswordVerifier::Scrypt(bad);
            assert!(bad.validate().is_err());
            assert!(!bad.verify(b"pw"));
        }
        for unknown in [
            r#"{"algorithm":"PBKDF2-HMAC-SHA-1","iterations":600000,"salt":"00","hash":"00"}"#,
            r#"{"algorithm":"PBKDF2-HMAC-SHA-256","iterations":600000,"salt":"00","hash":"00","extra":1}"#,
            r#"{"log_n":15,"r":8,"p":1,"salt":"00"}"#,
        ] {
            assert!(
                serde_json::from_str::<PasswordVerifier>(unknown).is_err(),
                "{unknown}"
            );
        }
        let user = |name: &str| PolicyUser {
            username: name.into(),
            password_scrypt: good.clone(),
            administrator: false,
            hashed_password: None,
            one_time_password: None,
        };
        validate_users(&[user("admin")]).unwrap();
        assert!(validate_users(&[user("admin"), user("admin")]).is_err());
        assert!(validate_users(&[user("")]).is_err());
        assert!(validate_users(&[user("a\nb")]).is_err());
        let device = |name: &str, serial: Option<&str>, id: Option<&str>| PolicyDevice {
            name: name.into(),
            device_serial_number: serial.map(Into::into),
            device_identifier: id.map(Into::into),
            network_identifier: None,
            machine_identifier: None,
            media_identifier: None,
            password_scrypt: good.clone(),
        };
        validate_devices(&[device("a", Some("1"), None), device("b", Some("2"), None)]).unwrap();
        // Device Identifier alone is not among the fields that SHALL be unique.
        assert!(validate_devices(&[device("a", None, Some("x"))]).is_err());
        assert!(
            validate_devices(&[
                device("a", Some("1"), Some("x")),
                device("b", Some("1"), None)
            ])
            .is_err()
        );
        assert!(
            validate_devices(&[device("a", Some("1"), None), device("a", Some("2"), None)])
                .is_err()
        );
        assert!(validate_devices(&[device("a", Some("1\n"), None)]).is_err());
    }
    #[test]
    fn totp_matches_the_rfc_6238_test_vectors() {
        let seed = |n: usize| b"1234567890".iter().copied().cycle().take(n).collect();
        for (digest, len, step59, step1111111109) in [
            (TotpDigest::Sha1, 20, "94287082", "07081804"),
            (TotpDigest::Sha256, 32, "46119246", "68084774"),
            (TotpDigest::Sha512, 64, "90693936", "25091201"),
        ] {
            let totp = TotpSecret {
                seed: seed(len),
                digest,
                digits: 8,
                interval: 30,
            };
            totp.validate().unwrap();
            assert_eq!(*totp.code(totp.step(59)), step59);
            assert_eq!(*totp.code(totp.step(1_111_111_109)), step1111111109);
            // One step of drift either way is accepted, two are not.
            assert_eq!(totp.matching_step(step59, 59 + 30), Some(1));
            assert_eq!(totp.matching_step(step59, 59 - 30), Some(1));
            assert_eq!(totp.matching_step(step59, 59 + 60), None);
            assert_eq!(totp.matching_step("9428708", 59), None);
        }
        let short = TotpSecret {
            seed: vec![1; 15],
            digest: TotpDigest::Sha1,
            digits: 6,
            interval: 30,
        };
        assert!(short.validate().is_err());
        for (digits, interval) in [(5, 30), (9, 30), (6, 10), (6, 301)] {
            let bad = TotpSecret {
                seed: vec![1; 20],
                digits,
                interval,
                ..short.clone()
            };
            assert!(bad.validate().is_err());
        }
        assert!(!format!("{short:?}").contains("seed"));
    }
    #[test]
    fn hashed_password_secret_recomputes_only_the_right_hash() {
        let secret = HashedPasswordSecret::new(HashName::Sha256, "Fred", "password1").unwrap();
        secret.validate().unwrap();
        let (s1, s2) = hashed_password_parts(HashName::Sha256, "Fred", "password1");
        assert_eq!(*s1, crate::crypto::sha256(b"Fredpassword1"));
        assert_eq!(*s2, crate::crypto::sha256(b"password1Fred"));
        let ts = 1_700_000_000_000_000i64;
        let first = HashName::Sha256.hash(&[&s1, &ts.to_be_bytes()]);
        assert!(secret.first_half_matches(ts, &first));
        assert!(!secret.first_half_matches(ts + 1, &first));
        assert!(!secret.first_half_matches(ts, &first[..31]));
        assert!(secret.s2_scrypt.verify(&s2));
        assert!(!secret.s2_scrypt.verify(&s1));
        let proof = secret.server_proof(ts, &s2);
        let expected = crate::crypto::sha256(
            &[&ts.to_be_bytes()[..], &s1, &crate::crypto::sha256(&s2)].concat(),
        );
        assert_eq!(proof, expected);
        let mut wrong = secret.clone();
        wrong.hashing_algorithm = HashName::Sha512;
        assert!(wrong.validate().is_err());
        assert!(!format!("{secret:?}").contains(&hex::encode(&secret.s1)));
    }
}
