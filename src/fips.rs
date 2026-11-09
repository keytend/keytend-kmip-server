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

//! FIPS mode (docs/fips.md).
//!
//! Every server-chosen default is an approved choice in both modes. FIPS mode
//! (`serve --fips`, `KMIP_FIPS=true`, or a host whose kernel reports FIPS
//! mode) only removes services that are not approved: it refuses them and does
//! not advertise them. Everything else is the same in both modes.
//!
//! The policy below is the server's own, applied before OpenSSL is called, so
//! a request is refused the same way whether or not the linked OpenSSL has a
//! FIPS provider. Sources for each row are in docs/fips.md: NIST SP 800-131A
//! Rev. 2 (transitions), FIPS 186-5 (signatures), SP 800-38A/D/F (AES modes),
//! SP 800-132 (PBKDF2), SP 800-56C Rev. 2 (HKDF), SP 800-52 Rev. 2 (TLS) and
//! the RHEL 9 OpenSSL FIPS provider security policy.
use anyhow::{Context, Result, ensure};
use std::cell::Cell;

thread_local! {
    /// Whether the request being processed on this thread is in FIPS mode.
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
}

/// Whether FIPS mode applies to the work running on this thread. The engine
/// sets it around each request (`scope`); it is off everywhere else.
pub fn active() -> bool {
    ACTIVE.with(Cell::get)
}

/// Run `f` with FIPS mode on or off on this thread, restoring the previous
/// setting afterwards (also on unwind).
pub fn scope<T>(enabled: bool, f: impl FnOnce() -> T) -> T {
    let _guard = enter(enabled);
    f()
}
/// Set the mode on this thread until the guard drops.
pub fn enter(enabled: bool) -> Guard {
    Guard(
        ACTIVE.with(|a| a.replace(enabled)),
        std::marker::PhantomData,
    )
}
/// Restores the previous mode; not `Send`, so it drops on its own thread.
pub struct Guard(bool, std::marker::PhantomData<*const ()>);
impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with(|a| a.set(self.0));
    }
}

/// A mechanism that FIPS mode does not offer. The protocol layer refuses
/// such requests first, with the reason its operation uses for an
/// unsupported mechanism; this error is the provider-layer backstop.
#[derive(Debug, thiserror::Error)]
#[error("{0} is not available in FIPS mode")]
pub struct NotApproved(pub &'static str);

/// Fail with `NotApproved` when FIPS mode is active.
pub fn refuse(what: &'static str) -> Result<()> {
    if active() {
        return Err(NotApproved(what).into());
    }
    Ok(())
}

/// The approved-mechanism table. Each predicate is pure; callers combine it
/// with `active()`.
pub mod approved {
    /// KMIP Cryptographic Algorithm values with an approved use: AES (3),
    /// RSA (4), ECDSA (6), HMAC-SHA-1/224/256/384/512 (7-11), ECDH (14),
    /// ECMQV (26) and HMAC-SHA3-224/256/384/512 (35-38). Not approved: DES
    /// and 3DES (1, 2; SP 800-131A Rev. 2 section 2), DSA (5; FIPS 186-5
    /// removed DSA signature generation and the RHEL 9 provider has no DSA),
    /// HMAC-MD5 (12), ChaCha20, Poly1305 and ChaCha20-Poly1305 (28-30).
    pub fn algorithm(algorithm: u32) -> bool {
        matches!(algorithm, 3 | 4 | 6..=11 | 14 | 26 | 35..=38)
    }
    /// KMIP Recommended Curve values: P-224 (4), P-256 (7), P-384 (10) and
    /// P-521 (13), the SP 800-186 prime curves in the provider.
    pub fn curve(curve: u32) -> bool {
        matches!(curve, 4 | 7 | 10 | 13)
    }
    /// Hashing Algorithm values for signatures: SHA-224 through SHA-512 and
    /// SHA3. SP 800-131A Rev. 2 Table 8 disallows SHA-1 for signature
    /// generation and allows it for verification as legacy use, but the RHEL 9
    /// provider refuses SHA-1 in RSA and ECDSA signatures in both directions
    /// ("digest not allowed"), so FIPS mode neither signs nor verifies with
    /// it. SHA-1 stays available for hashing, HMAC, OAEP, MGF1 verification
    /// and PBKDF2.
    pub fn signature_hash(hash: u32) -> bool {
        matches!(hash, 5..=8 | 12..=17)
    }
    /// MGF1 hash of an RSA-PSS signature being verified: SHA-1 too (the
    /// provider accepts it; SP 800-131A Rev. 2 legacy use).
    pub fn verification_mgf_hash(hash: u32) -> bool {
        hash == 4 || signature_hash(hash)
    }
    /// RSA modulus for signature generation and key transport (SP 800-131A
    /// Rev. 2 sections 3 and 6).
    pub const MIN_RSA_BITS: u32 = 2048;
    /// RSA signature verification at 1024 bits and up is legacy use.
    pub const MIN_RSA_VERIFY_BITS: u32 = 1024;
    /// HMAC generation and KDF keys need 112-bit security (SP 800-131A
    /// Rev. 2 section 10; SP 800-132 section 5.3; SP 800-56C Rev. 2).
    pub const MIN_KEY_BYTES: usize = 14;
    /// AES-GCM tags of 96 bits and more (SP 800-38D section 5.2.1.2; the
    /// 32- and 64-bit tags need the Appendix C limits the server cannot
    /// enforce).
    pub fn gcm_tag(bytes: usize) -> bool {
        (12..=16).contains(&bytes)
    }
    /// Server-generated AES-GCM IVs: at least 96 random bits (SP 800-38D
    /// section 8.2.2; FIPS 140-3 IG C.H scenario 2).
    pub const MIN_GCM_RANDOM_IV_BITS: u32 = 96;
    /// KMIP Derivation Method values: PBKDF2 (1, SP 800-132) and HKDF (10,
    /// SP 800-56C Rev. 2), both computed inside the provider. HASH, HMAC
    /// and ENCRYPT (2-4) and the AWS Signature Version 4 chain (9) are not
    /// approved KDFs; the SP 800-108 methods (5-7) are composed by this
    /// server from HMAC/CMAC calls outside the validated module.
    pub fn derivation_method(method: u32) -> bool {
        matches!(method, 1 | 10)
    }
    /// SP 800-132 section 5.1 (salt of at least 128 bits) and 5.2
    /// (iteration count of at least 1000), as the provider enforces.
    pub const MIN_PBKDF2_SALT_BYTES: usize = 16;
    pub const MIN_PBKDF2_ITERATIONS: usize = 1000;
    /// PBKDF2 passwords of at least 8 bytes. SP 800-132 sets no minimum; the
    /// RHEL 9 provider refuses shorter ones, for Derive Key and password
    /// verifiers alike.
    pub const MIN_PBKDF2_PASSWORD_BYTES: usize = 8;
    /// FIPS 186-5 section 5.4 (g): 0 <= sLen <= hLen for RSASSA-PSS.
    pub fn pss_salt(salt: i32, hash_bytes: usize) -> bool {
        salt >= 0 && salt as usize <= hash_bytes
    }
}

/// TLS settings of the approved default policy (`modern`) and of the
/// server-to-client connector: SP 800-52 Rev. 2 section 3.3.1 suites with
/// AES-GCM and ephemeral ECDH, the NIST curves P-256, P-384 and P-521, and
/// RSA, RSA-PSS and ECDSA signatures with SHA-2. ChaCha20-Poly1305,
/// X25519/X448 and EdDSA are left to explicit non-default policies.
///
/// Finite-field DHE (TLS 1.2 DHE-RSA suites and the TLS 1.3 FFDHE groups) is
/// approved but not in the default either: it is the only path into the
/// server-side modular exponentiation of CVE-2024-41996 (an unauthenticated
/// client can make the server do expensive DH public-key checks).
/// `--tls-profile mozilla-intermediate` still enables it.
pub mod tls {
    pub const TLS12_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";
    pub const TLS13_SUITES: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
    pub const GROUPS: &str = "secp256r1:secp384r1:secp521r1";
    pub const SIGALGS: &str = "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA+SHA256:RSA+SHA384:RSA+SHA512";
    /// Restrict a TLS context to the approved lists. Fails if the linked
    /// OpenSSL lacks any of them.
    pub fn restrict(builder: &mut openssl::ssl::SslContextBuilder) -> anyhow::Result<()> {
        builder.set_cipher_list(TLS12_CIPHERS)?;
        builder.set_ciphersuites(TLS13_SUITES)?;
        builder.set_groups_list(GROUPS)?;
        builder.set_sigalgs_list(SIGALGS)?;
        Ok(())
    }
}

/// Whether the host kernel runs in FIPS mode (`/proc/sys/crypto/fips_enabled`
/// is 1). Such a host must not run a server outside FIPS mode.
pub fn host_requires() -> bool {
    std::fs::read_to_string("/proc/sys/crypto/fips_enabled").is_ok_and(|s| s.trim() == "1")
}

/// What `load_provider` found.
#[derive(Debug, serde::Serialize)]
pub struct ProviderStatus {
    /// The linked libcrypto (`OpenSSL_version(OPENSSL_VERSION)`).
    pub library: &'static str,
    /// Providers this process loaded explicitly.
    pub loaded: Vec<&'static str>,
    /// What each loaded provider reports about itself, in `loaded` order.
    pub providers: Vec<ProviderDetails>,
    /// The provider's power-on self-tests run while it loads; a failure
    /// makes the load fail.
    pub self_tests: &'static str,
    /// Checks of the default library context after loading.
    pub checks: Vec<String>,
}

/// A loaded provider's own name, version, build information and status
/// (`OSSL_PROVIDER_get_params`, read by the `ossl-provider-info` crate). A
/// field is absent when the provider does not report it.
#[derive(Debug, serde::Serialize)]
pub struct ProviderDetails {
    /// The name the provider was loaded by ("fips", "base").
    pub id: &'static str,
    pub name: Option<String>,
    pub version: Option<String>,
    pub build_info: Option<String>,
    /// 1 while the provider runs; 0 after it entered its error state.
    pub status: Option<i32>,
}

impl ProviderDetails {
    fn read(id: &'static str, provider: &openssl::provider::Provider) -> Result<Self> {
        let info = ossl_provider_info::provider_info(provider)
            .with_context(|| format!("the \"{id}\" provider does not report its parameters"))?;
        Ok(Self {
            id,
            name: info.name,
            version: info.version,
            build_info: info.build_info,
            status: info.status,
        })
    }
}

static PROVIDERS: std::sync::OnceLock<Vec<openssl::provider::Provider>> =
    std::sync::OnceLock::new();

/// Load OpenSSL's "fips" provider (and "base" for encoders and decoders) into
/// the default library context, then confirm that only FIPS implementations
/// can be fetched. Loading a provider explicitly disables the automatic
/// fallback to the "default" provider; a configuration that activates
/// another provider without `default_properties = fips=yes` is refused here
/// rather than silently mixing implementations. Call before any other
/// OpenSSL use. Each provider's own name, version, build information and
/// status are read back; the "fips" provider must report status 1 (running,
/// not in its error state).
pub fn load_provider() -> Result<ProviderStatus> {
    use openssl::provider::Provider;
    let fips = Provider::load(None, "fips").context(
        "cannot load the OpenSSL \"fips\" provider (missing module or configuration, or its self-tests failed)",
    )?;
    let base = Provider::load(None, "base").context("cannot load the OpenSSL \"base\" provider")?;
    let providers = vec![
        ProviderDetails::read("fips", &fips)?,
        ProviderDetails::read("base", &base)?,
    ];
    ensure!(
        providers[0].status == Some(1),
        "the OpenSSL \"fips\" provider is not running (status {:?})",
        providers[0].status
    );
    let checks = verify_context()?;
    let _ = PROVIDERS.set(vec![fips, base]);
    Ok(ProviderStatus {
        library: openssl::version::version(),
        loaded: vec!["fips", "base"],
        providers,
        self_tests: "passed (the provider loaded)",
        checks,
    })
}

/// What the providers `load_provider` loaded report now, read again on each
/// call so that a provider which entered its error state after start shows
/// status 0 (metrics.rs). Empty outside FIPS mode, where none was loaded.
pub fn loaded_providers() -> Vec<ProviderDetails> {
    let ids = ["fips", "base"];
    PROVIDERS
        .get()
        .map(|providers| {
            providers
                .iter()
                .zip(ids)
                .filter_map(|(provider, id)| ProviderDetails::read(id, provider).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The default library context offers FIPS SHA-256 and AES-256-GCM and none
/// of the non-approved MD5, BLAKE2b or ChaCha20-Poly1305; a SHA-256 known
/// answer goes through the EVP path the server uses.
fn verify_context() -> Result<Vec<String>> {
    use openssl::{cipher::Cipher, md::Md};
    let mut checks = vec![];
    Md::fetch(None, "SHA2-256", Some("fips=yes")).context("the fips provider offers no SHA-256")?;
    Cipher::fetch(None, "AES-256-GCM", Some("fips=yes"))
        .context("the fips provider offers no AES-256-GCM")?;
    checks.push("SHA2-256 and AES-256-GCM fetched with fips=yes".to_owned());
    for name in ["MD5", "BLAKE2B-512"] {
        ensure!(
            Md::fetch(None, name, None).is_err(),
            "the non-FIPS digest {name} is available: another provider (such as \"default\") is active without default_properties = fips=yes"
        );
    }
    ensure!(
        Cipher::fetch(None, "ChaCha20-Poly1305", None).is_err(),
        "the non-FIPS cipher ChaCha20-Poly1305 is available: another provider is active without default_properties = fips=yes"
    );
    checks.push("MD5, BLAKE2B-512 and ChaCha20-Poly1305 unavailable".to_owned());
    let answer = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), b"abc")?;
    ensure!(
        hex::encode(answer) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 known-answer test failed"
    );
    checks.push("SHA-256 known answer through EVP".to_owned());
    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_sets_and_restores_the_thread_mode() {
        assert!(!active());
        scope(true, || {
            assert!(active());
            assert!(refuse("x").is_err());
            scope(false, || assert!(!active()));
            assert!(active());
        });
        assert!(!active());
        assert!(refuse("x").is_ok());
        let unwound = std::panic::catch_unwind(|| scope(true, || panic!("boom")));
        assert!(unwound.is_err());
        assert!(!active());
    }

    #[test]
    fn approved_table_rows() {
        for a in [3, 4, 6, 7, 8, 9, 10, 11, 14, 26, 35, 36, 37, 38] {
            assert!(approved::algorithm(a), "{a}");
        }
        for a in [0, 1, 2, 5, 12, 13, 15, 28, 29, 30] {
            assert!(!approved::algorithm(a), "{a}");
        }
        for c in [4, 7, 10, 13] {
            assert!(approved::curve(c));
        }
        for c in [1, 2, 25, 55, 61, 68] {
            assert!(!approved::curve(c));
        }
        assert!(!approved::signature_hash(4) && !approved::signature_hash(3));
        assert!(approved::signature_hash(6) && approved::signature_hash(17));
        assert!(approved::verification_mgf_hash(4) && approved::verification_mgf_hash(6));
        assert!(approved::gcm_tag(12) && !approved::gcm_tag(8));
        assert!(approved::derivation_method(1) && approved::derivation_method(10));
        for m in [2, 3, 4, 5, 6, 7, 8, 9] {
            assert!(!approved::derivation_method(m));
        }
        assert!(approved::pss_salt(32, 32) && !approved::pss_salt(64, 32));
        assert!(!approved::pss_salt(-2, 32));
    }

    #[test]
    fn approved_tls_lists_load_in_the_linked_openssl() {
        let mut b = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls()).unwrap();
        tls::restrict(&mut b).unwrap();
        for name in ["CHACHA", "x25519", "X25519", "ed25519", "SHA1"] {
            assert!(!tls::TLS12_CIPHERS.contains(name));
            assert!(!tls::TLS13_SUITES.contains(name));
            assert!(!tls::GROUPS.contains(name));
            assert!(!tls::SIGALGS.contains(name));
        }
    }
}
