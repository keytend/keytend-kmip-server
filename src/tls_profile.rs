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

//! TLS policies for the TTLV and HTTPS listeners (`--tls-profile`).
//!
//! `modern` (the default) is the Mozilla intermediate v5 configuration
//! restricted to FIPS-approved suites, groups and signature algorithms
//! (`keytend_kmip_server::fips::tls`); `mozilla-intermediate` is the unrestricted
//! configuration, with ChaCha20-Poly1305, X25519/X448 and EdDSA. Neither is
//! tied to a KMIP authentication suite. Every other policy is taken
//! from authentication suites in the pinned Profiles documents. It enables
//! exactly the protocol versions, cipher suites and key-exchange groups below
//! and nothing else. `docs/specs/tls-profile-inventory.json` records the
//! per-edition lists, and the unit tests check each policy against that file
//! and against live handshakes. See docs/tls-profiles.md.

use anyhow::{Context, Result, bail};
use openssl::{
    nid::Nid,
    pkey::Id,
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslOptions, SslVerifyMode, SslVersion},
    x509::{X509, X509Ref, X509StoreContextRef, X509VerifyResult},
};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum TlsProfile {
    /// TLS 1.2 and 1.3 with ECDHE AES-GCM suites, the NIST curves P-256,
    /// P-384 and P-521 and SHA-2 RSA/ECDSA signatures (FIPS-approved). No
    /// finite-field DHE. Not a KMIP authentication suite.
    #[default]
    Modern,
    /// Mozilla intermediate v5 as OpenSSL ships it, which adds
    /// ChaCha20-Poly1305, X25519/X448, EdDSA and finite-field DHE (DHE-RSA
    /// suites, FFDHE groups). Not FIPS-approved.
    #[value(name = "mozilla-intermediate")]
    MozillaIntermediate,
    /// Profiles 2.0, 2.1 and 3.0 Basic and HTTPS suites with TLS 1.3 only.
    #[value(name = "kmip-2-basic")]
    Kmip2Basic,
    /// Profiles 2.0, 2.1 and 3.0 Basic with the optional TLS 1.2, which
    /// brings in the mandatory static-RSA suites. Legacy.
    #[value(name = "kmip-2-basic-tls12")]
    Kmip2BasicTls12,
    /// Profiles 1.1-1.4 TLS 1.2 Authentication Suite and 1.4 Basic/HTTPS. Legacy.
    #[value(name = "kmip-1-tls12")]
    Kmip1Tls12,
    /// Profiles 1.1-1.3 Basic and 1.3 HTTPS suites: TLS 1.0-1.2. Legacy.
    #[value(name = "kmip-1-basic")]
    Kmip1Basic,
    /// Profiles 1.3/1.4 Suite B minLOS_128 (3.3, 5.13): column 1 only
    /// (AES-128-GCM, P-256, SHA-256) and ECDSA-256 authentication.
    /// `kmip-1-suite-b` is accepted as an alias.
    #[value(name = "kmip-1-suite-b-128", alias = "kmip-1-suite-b")]
    Kmip1SuiteB128,
    /// Profiles 1.3/1.4 Suite B minLOS_192 (3.4, 5.13): column 2 only and
    /// ECDSA-384 authentication on both sides.
    #[value(name = "kmip-1-suite-b-192")]
    Kmip1SuiteB192,
    /// Profiles 3.0 CSD02 (draft) Quantum Safe suite.
    #[value(name = "kmip-3-quantum-safe")]
    Kmip3QuantumSafe,
}

/// A TLS 1.0-1.2 cipher suite: IANA name and OpenSSL name.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Suite {
    pub iana: &'static str,
    #[serde(skip)]
    pub openssl: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Credential {
    /// Any server key: TLS 1.3 suites do not depend on the certificate type.
    Any,
    /// Mandatory static-RSA or ECDHE-RSA suites need an RSA server key.
    Rsa,
    /// Suite B minLOS_128 (column 1) needs an ECDSA key on P-256.
    EcdsaP256,
    /// Suite B minLOS_192 needs an ECDSA key on P-384.
    EcdsaP384,
}

/// A Suite B minimum level of security (Profiles 1.3/1.4 section 5.13).
///
/// The level selects OpenSSL's RFC 6460 Suite B mode, which ties each suite
/// to its column: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 runs only with
/// ECDHE on P-256 and TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 only with
/// P-384. It also ties both certificate keys to that column (P-256 keys
/// signing with SHA-256 for AES-128, P-384 with SHA-384 for AES-256), and it
/// requires every certificate of the peer's chain to be an X.509 v3
/// certificate with a P-256 or P-384 key, signed with the hash of its
/// issuer's curve. The policy adds the digitalSignature key usage that 5.13
/// requires of each end-entity certificate.
///
/// Because the certificate curves follow the column, a server can negotiate
/// the 3.3.2 suite (AES-128) only with a P-256 key. minLOS_128 is therefore
/// column 1 alone, which 5.13 allows ("exclusively from Column 1 or
/// exclusively from Column 2"). The cost is that a client authenticating
/// with ECDSA-384 at minLOS_128, which 5.13 calls allowable, is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuiteB {
    MinLos128,
    MinLos192,
}
impl SuiteB {
    /// The certificate verification flags Suite B mode sets at this level,
    /// for verification outside a handshake (`main::listener_verifier`).
    pub fn verify_flags(self) -> openssl::x509::verify::X509VerifyFlags {
        use openssl::x509::verify::X509VerifyFlags;
        match self {
            Self::MinLos128 => X509VerifyFlags::SUITEB_128_LOS,
            Self::MinLos192 => X509VerifyFlags::SUITEB_192_LOS,
        }
    }
    /// The OpenSSL cipher string that enables Suite B mode at this level.
    fn cipher_string(self) -> &'static str {
        match self {
            Self::MinLos128 => "SUITEB128",
            Self::MinLos192 => "SUITEB192",
        }
    }
    /// Signature algorithms a certificate in a chain at this level may
    /// carry. Profiles 1.3/1.4 section 5.13 defines the two Suite B
    /// signatures, ECDSA-256 (P-256 with SHA-256) and ECDSA-384 (P-384 with
    /// SHA-384); minLOS_192 allows only ECDSA-384. Suite B mode applies the
    /// same rule to every certificate it sends or receives (signed with the
    /// hash of its issuer's curve), so a server certificate signed otherwise
    /// can never complete a handshake.
    fn signatures(self) -> &'static [Nid] {
        match self {
            Self::MinLos128 => &[Nid::ECDSA_WITH_SHA256, Nid::ECDSA_WITH_SHA384],
            Self::MinLos192 => &[Nid::ECDSA_WITH_SHA384],
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Policy {
    pub name: &'static str,
    #[serde(serialize_with = "versions")]
    pub versions: &'static [SslVersion],
    /// Suites for TLS 1.0-1.2, in server preference order.
    pub tls12_suites: &'static [Suite],
    /// TLS 1.3 suites (RFC 8446 names), in server preference order.
    pub tls13_suites: &'static [&'static str],
    /// OpenSSL group names. Empty: no suite of the policy uses a group.
    pub groups: &'static [&'static str],
    pub credential: Credential,
    /// Suite B level: OpenSSL's Suite B mode and the certificate checks of
    /// Profiles 1.3/1.4 section 5.13.
    pub suite_b: Option<SuiteB>,
    /// TLS 1.0/1.1 need OpenSSL security level 0. Compensating checks then
    /// keep certificate keys and signatures and TLS 1.2 signature algorithms
    /// at security level 2 strength.
    pub security_level_0: bool,
    /// Logged at startup when the policy is selected.
    pub warning: Option<&'static str>,
    /// Authentication suites the policy is taken from: (edition, suite) keys
    /// of `docs/specs/tls-profile-inventory.json`.
    pub derived_from: &'static [(&'static str, &'static str)],
}

fn versions<S: serde::Serializer>(v: &&'static [SslVersion], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(v.iter().map(|v| version_name(*v)))
}

pub fn version_name(v: SslVersion) -> &'static str {
    match v {
        SslVersion::TLS1 => "TLSv1.0",
        SslVersion::TLS1_1 => "TLSv1.1",
        SslVersion::TLS1_2 => "TLSv1.2",
        SslVersion::TLS1_3 => "TLSv1.3",
        _ => "other",
    }
}

const fn suite(iana: &'static str, openssl: &'static str) -> Suite {
    Suite { iana, openssl }
}

/// TLS 1.3 suites of Profiles 2.0-3.0 3.1.2 ("TLS13-AES-256-GCM-SHA384" and
/// "TLS13-CHACHA20-POLY1305-SHA256" in the source spelling). TLS_AES_128_GCM_SHA256,
/// which RFC 8446 9.1 makes mandatory to implement unless an application
/// profile says otherwise, is not listed and is therefore not enabled.
const BASIC_TLS13: &[&str] = &["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"];
/// The Basic suites name no groups. These are pinned so that every linked
/// OpenSSL negotiates the same groups. They are a server choice, not a
/// profile requirement.
const CLASSICAL_GROUPS: &[&str] = &["x25519", "secp256r1", "secp384r1"];
/// Profiles 1.4 3.1.2, 1.1-1.4 3.2.2 and 2.0-3.0 3.1.2 (if TLS 1.2): mandatory suites.
const STATIC_RSA_SHA256: [Suite; 2] = [
    suite("TLS_RSA_WITH_AES_256_CBC_SHA256", "AES256-SHA256"),
    suite("TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256"),
];

const LEGACY_STATIC_RSA: &str = "static-RSA key exchange without forward secrecy and CBC suites are enabled because the selected KMIP profile requires them; use only for clients that cannot use the kmip-2-basic or modern policies";

pub static POLICIES: &[Policy] = &[
    Policy {
        name: "kmip-2-basic",
        versions: &[SslVersion::TLS1_3],
        tls12_suites: &[],
        tls13_suites: BASIC_TLS13,
        groups: CLASSICAL_GROUPS,
        credential: Credential::Any,
        suite_b: None,
        security_level_0: false,
        warning: None,
        derived_from: &[
            ("2.0", "basic"),
            ("2.0", "https"),
            ("2.1", "basic"),
            ("2.1", "https"),
            ("3.0-csd02", "basic"),
            ("3.0-csd02", "https"),
        ],
    },
    Policy {
        name: "kmip-2-basic-tls12",
        versions: &[SslVersion::TLS1_2, SslVersion::TLS1_3],
        // The two ECDHE-RSA suites are from the 2.x MAY list. They come first so
        // that clients offering them get forward secrecy.
        tls12_suites: &[
            suite(
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "ECDHE-RSA-AES256-SHA384",
            ),
            suite(
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "ECDHE-RSA-AES128-SHA256",
            ),
            STATIC_RSA_SHA256[0],
            STATIC_RSA_SHA256[1],
        ],
        tls13_suites: BASIC_TLS13,
        groups: CLASSICAL_GROUPS,
        credential: Credential::Rsa,
        suite_b: None,
        security_level_0: false,
        warning: Some(LEGACY_STATIC_RSA),
        derived_from: &[
            ("2.0", "basic"),
            ("2.0", "https"),
            ("2.1", "basic"),
            ("2.1", "https"),
            ("3.0-csd02", "basic"),
            ("3.0-csd02", "https"),
        ],
    },
    Policy {
        name: "kmip-1-tls12",
        versions: &[SslVersion::TLS1_2],
        // Only the mandatory suites. The 1.1 MAY list is defined by NIST
        // SP 800-57 Part 3 tables, which are not pinned here.
        tls12_suites: &STATIC_RSA_SHA256,
        tls13_suites: &[],
        groups: &[],
        credential: Credential::Rsa,
        suite_b: None,
        security_level_0: false,
        warning: Some(LEGACY_STATIC_RSA),
        derived_from: &[
            ("1.1", "tls12"),
            ("1.2", "tls12"),
            ("1.3", "tls12"),
            ("1.4", "tls12"),
            ("1.4", "basic"),
            ("1.4", "https"),
        ],
    },
    Policy {
        name: "kmip-1-basic",
        versions: &[SslVersion::TLS1, SslVersion::TLS1_1, SslVersion::TLS1_2],
        tls12_suites: &[suite("TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA")],
        tls13_suites: &[],
        groups: &[],
        credential: Credential::Rsa,
        suite_b: None,
        security_level_0: true,
        warning: Some(
            "TLS 1.0 and 1.1 with static-RSA CBC key exchange (no forward secrecy) are enabled because KMIP 1.1-1.3 Basic requires them; the OpenSSL security level is 0 with compensating certificate and signature checks; use only for clients that cannot use TLS 1.2",
        ),
        derived_from: &[
            ("1.1", "basic"),
            ("1.2", "basic"),
            ("1.3", "basic"),
            ("1.3", "https"),
        ],
    },
    Policy {
        name: "kmip-1-suite-b-128",
        versions: &[SslVersion::TLS1_2],
        // 3.3.2 and 5.13 column 1: AES-128, ECDH on P-256, SHA-256. With a
        // P-256 server key Suite B mode never negotiates the column 2 suite.
        tls12_suites: &[suite(
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
        )],
        tls13_suites: &[],
        groups: &["secp256r1"],
        credential: Credential::EcdsaP256,
        suite_b: Some(SuiteB::MinLos128),
        security_level_0: false,
        warning: None,
        derived_from: &[("1.3", "suite_b_128"), ("1.4", "suite_b_128")],
    },
    Policy {
        name: "kmip-1-suite-b-192",
        versions: &[SslVersion::TLS1_2],
        // 3.4.2; 5.13: minLOS_192 uses column 2 only.
        tls12_suites: &[suite(
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
        )],
        tls13_suites: &[],
        groups: &["secp384r1"],
        credential: Credential::EcdsaP384,
        suite_b: Some(SuiteB::MinLos192),
        security_level_0: false,
        warning: None,
        derived_from: &[("1.3", "suite_b_192"), ("1.4", "suite_b_192")],
    },
    Policy {
        name: "kmip-3-quantum-safe",
        versions: &[SslVersion::TLS1_3],
        tls12_suites: &[],
        tls13_suites: BASIC_TLS13,
        groups: &["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"],
        credential: Credential::Any,
        suite_b: None,
        security_level_0: false,
        warning: None,
        derived_from: &[("3.0-csd02", "quantum_safe")],
    },
];

impl TlsProfile {
    /// The fixed policy, or None for `modern` and `mozilla-intermediate`.
    pub fn policy(self) -> Option<&'static Policy> {
        let name = match self {
            Self::Modern | Self::MozillaIntermediate => return None,
            Self::Kmip2Basic => "kmip-2-basic",
            Self::Kmip2BasicTls12 => "kmip-2-basic-tls12",
            Self::Kmip1Tls12 => "kmip-1-tls12",
            Self::Kmip1Basic => "kmip-1-basic",
            Self::Kmip1SuiteB128 => "kmip-1-suite-b-128",
            Self::Kmip1SuiteB192 => "kmip-1-suite-b-192",
            Self::Kmip3QuantumSafe => "kmip-3-quantum-safe",
        };
        POLICIES.iter().find(|p| p.name == name)
    }
}

impl TlsProfile {
    /// Policies whose versions, suites, groups and signatures are all
    /// FIPS-approved (SP 800-52 Rev. 2): the only ones FIPS mode starts with.
    /// The others need ChaCha20-Poly1305, X25519, static-RSA (PKCS#1 v1.5)
    /// key transport, or TLS 1.0/1.1.
    pub fn fips_approved(self) -> bool {
        matches!(
            self,
            Self::Modern | Self::Kmip1SuiteB128 | Self::Kmip1SuiteB192
        )
    }
}

/// TLS 1.2 signature algorithms when the security level is 0: no SHA-1 or MD5.
const STRONG_SIGALGS: &str = "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448";

/// Restrict a Mozilla intermediate acceptor to `policy`. Fails when the
/// server certificate cannot serve the policy's suites or when the linked
/// OpenSSL lacks a listed suite or group. Call after `set_verify`, because
/// the security-level-0 policy replaces the verify callback.
pub fn apply(builder: &mut SslAcceptorBuilder, policy: &Policy, certificate: &X509) -> Result<()> {
    check_credential(policy, certificate)?;
    let level = if policy.security_level_0 {
        ":@SECLEVEL=0"
    } else {
        ""
    };
    // set_cipher_list silently drops unknown names when some name matches, so
    // each suite is first checked on its own.
    let mut scratch = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    for s in policy.tls12_suites {
        scratch
            .set_cipher_list(&format!("{}{level}", s.openssl))
            .with_context(|| {
                format!(
                    "TLS profile {}: the linked {} does not provide {}",
                    policy.name,
                    openssl::version::version(),
                    s.iana
                )
            })?;
    }
    // Versions come only from the min/max range.
    builder.clear_options(SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
    builder.set_min_proto_version(policy.versions.first().copied())?;
    builder.set_max_proto_version(policy.versions.last().copied())?;
    if let Some(suite_b) = policy.suite_b {
        // The keyword must start the cipher string to select Suite B mode.
        builder.set_cipher_list(suite_b.cipher_string())?;
    } else if !policy.tls12_suites.is_empty() {
        let list: Vec<_> = policy.tls12_suites.iter().map(|s| s.openssl).collect();
        builder.set_cipher_list(&format!("{}{level}", list.join(":")))?;
    }
    if !policy.tls13_suites.is_empty() {
        builder.set_ciphersuites(&policy.tls13_suites.join(":"))?;
    }
    if !policy.groups.is_empty() {
        builder
            .set_groups_list(&policy.groups.join(":"))
            .with_context(|| {
                format!(
                    "TLS profile {} needs the groups {} and the linked {} does not provide all of them",
                    policy.name,
                    policy.groups.join(", "),
                    openssl::version::version()
                )
            })?;
    }
    builder.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);
    if let Some(level) = policy.suite_b {
        suite_b_end_entity(certificate)
            .and_then(|()| suite_b_signature(level, certificate))
            .map_err(|e| anyhow::anyhow!("TLS profile {}: server certificate {e}", policy.name))?;
        builder.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            |ok, ctx| {
                supported_curve_chain(ok, ctx)
                    && strong_chain(true, ctx)
                    && suite_b_chain(true, ctx)
            },
        );
    }
    if policy.security_level_0 {
        certificate_strength(certificate)
            .map_err(|e| anyhow::anyhow!("TLS profile {}: server certificate {e}", policy.name))?;
        builder.set_sigalgs_list(STRONG_SIGALGS)?;
        builder.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            |ok, ctx| supported_curve_chain(ok, ctx) && strong_chain(true, ctx),
        );
    }
    Ok(())
}

fn check_credential(policy: &Policy, certificate: &X509) -> Result<()> {
    let key = certificate.public_key()?;
    let ok = match policy.credential {
        Credential::Any => true,
        Credential::Rsa => key.id() == Id::RSA,
        Credential::EcdsaP256 => {
            key.id() == Id::EC && key.ec_key()?.group().curve_name() == Some(Nid::X9_62_PRIME256V1)
        }
        Credential::EcdsaP384 => {
            key.id() == Id::EC && key.ec_key()?.group().curve_name() == Some(Nid::SECP384R1)
        }
    };
    if !ok {
        bail!(
            "TLS profile {} needs a {} server certificate",
            policy.name,
            match policy.credential {
                Credential::Rsa => "RSA",
                Credential::EcdsaP384 => "P-384 ECDSA",
                Credential::EcdsaP256 => "P-256 ECDSA",
                Credential::Any => "any",
            }
        );
    }
    Ok(())
}

/// Security level 2 rules for one certificate: a key of at least 112-bit
/// strength and, unless self-signed, no MD2/MD4/MD5/SHA-1 signature.
pub fn certificate_strength(cert: &X509Ref) -> Result<(), String> {
    let bits = cert
        .public_key()
        .map_err(|e| e.to_string())?
        .security_bits();
    if bits < 112 {
        return Err(format!("key has {bits}-bit security, below 112"));
    }
    if cert.issued(cert) != X509VerifyResult::OK {
        let digest = cert
            .signature_algorithm()
            .object()
            .nid()
            .signature_algorithms()
            .map(|a| a.digest);
        if matches!(
            digest,
            Some(Nid::MD2 | Nid::MD4 | Nid::MD5 | Nid::MD5_SHA1 | Nid::SHA1)
        ) {
            return Err("is signed with a weak digest".into());
        }
    }
    Ok(())
}

/// Whether a certificate's EC subject key, if any, is on a curve the server
/// implements (docs/interpretations.md#supported-elliptic-curves). Read
/// from the DER, as for KMIP requests, so every OpenSSL build answers alike.
/// TLS keeps all 13 implemented curves whatever `--ec-curves` says: that
/// setting governs KMIP operations only.
pub fn supported_curve(cert: &X509Ref) -> bool {
    cert.to_der().is_ok_and(|der| {
        keytend_kmip_server::crypto::ec::certificate_curve(&der)
            .is_none_or(keytend_kmip_server::crypto::ec::implemented)
    })
}
/// Every listener: a peer chain certificate on an unsupported curve is
/// refused. Applied by `main::tls` for every policy.
pub fn supported_curve_chain(preverified: bool, ctx: &mut X509StoreContextRef) -> bool {
    if !preverified {
        return false;
    }
    match ctx.current_cert().map(supported_curve) {
        Some(true) => true,
        Some(false) => {
            tracing::warn!(
                depth = ctx.error_depth(),
                "peer certificate refused: unsupported EC curve"
            );
            ctx.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
            false
        }
        None => false,
    }
}
/// Every listener: each peer chain certificate meets [`certificate_strength`]
/// (NIST SP 800-131A: no SHA-1 or weaker signatures, keys of at least 112-bit
/// strength). Applied by `main::tls` for every policy.
pub fn strong_chain(preverified: bool, ctx: &mut X509StoreContextRef) -> bool {
    if !preverified {
        return false;
    }
    match ctx.current_cert().map(certificate_strength) {
        Some(Ok(())) => true,
        Some(Err(reason)) => {
            tracing::warn!(depth = ctx.error_depth(), %reason, "peer certificate refused by the TLS profile");
            ctx.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
            false
        }
        None => false,
    }
}

/// Profiles 1.3/1.4 section 5.13: each product uses "an X.509 certificate
/// that ... contains an elliptic curve public key with the key usage bit set
/// for digital signature". The key's curve and the chain's algorithms are
/// checked by OpenSSL's Suite B mode; this adds the version and the key
/// usage, which must be present and include digitalSignature.
pub fn suite_b_end_entity(cert: &X509Ref) -> Result<(), String> {
    if cert.version() != 2 {
        return Err("is not an X.509 v3 certificate".into());
    }
    if cert.public_key().map_err(|e| e.to_string())?.id() != Id::EC {
        return Err("has no elliptic curve key".into());
    }
    let der = cert.to_der().map_err(|e| e.to_string())?;
    let usage = keytend_kmip_server::crypto::certificate_attributes::inspect(&der)
        .map_err(|e| format!("cannot be read: {e:#}"))?
        .key_usage;
    // RFC 5280 named bit 0.
    match usage {
        Some(bits) if bits & 1 != 0 => Ok(()),
        _ => Err("lacks the digitalSignature key usage".into()),
    }
}

/// The server certificate's own signature under a Suite B policy
/// (`SuiteB::signatures`). Without this check the listener would start and
/// then refuse every handshake for lack of a usable certificate.
fn suite_b_signature(level: SuiteB, cert: &X509Ref) -> Result<(), String> {
    let nid = cert.signature_algorithm().object().nid();
    if level.signatures().contains(&nid) {
        return Ok(());
    }
    let allowed: Vec<_> = level
        .signatures()
        .iter()
        .filter_map(|n| n.short_name().ok())
        .collect();
    Err(format!(
        "is signed with {}, not {}",
        nid.short_name().unwrap_or("an unknown algorithm"),
        allowed.join(" or ")
    ))
}

/// Peer chains under a Suite B policy: OpenSSL's verdict (including its
/// Suite B chain rules), then the end-entity rules of 5.13.
fn suite_b_chain(preverified: bool, ctx: &mut X509StoreContextRef) -> bool {
    if !preverified {
        return false;
    }
    if ctx.error_depth() != 0 {
        return true;
    }
    match ctx.current_cert().map(suite_b_end_entity) {
        Some(Ok(())) => true,
        Some(Err(reason)) => {
            tracing::warn!(%reason, "peer certificate refused by the Suite B policy");
            ctx.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
            false
        }
        None => false,
    }
}

/// The policies as JSON, for `keytend-kmip-server tls-profiles` and evidence harnesses.
pub fn describe() -> serde_json::Value {
    serde_json::json!({
        "default": "modern",
        "modern": {
            "description": "Mozilla intermediate v5 (TLS 1.2-1.3) restricted to FIPS-approved choices; not a KMIP authentication suite",
            "tls12_ciphers": keytend_kmip_server::fips::tls::TLS12_CIPHERS,
            "tls13_suites": keytend_kmip_server::fips::tls::TLS13_SUITES,
            "groups": keytend_kmip_server::fips::tls::GROUPS,
            "signature_algorithms": keytend_kmip_server::fips::tls::SIGALGS,
        },
        "mozilla-intermediate": "Mozilla intermediate v5 as shipped by the linked OpenSSL (adds ChaCha20-Poly1305, X25519/X448, EdDSA); not FIPS-approved",
        "fips_mode_policies": ["modern", "kmip-1-suite-b-128", "kmip-1-suite-b-192"],
        "openssl": openssl::version::version(),
        "policies": POLICIES,
    })
}

#[cfg(test)]
mod tests {
    //! Every policy against the production acceptor built by `crate::tls`.
    //! For each policy, every listed version, suite and group negotiates and
    //! every other one the linked OpenSSL implements is refused.
    use super::*;
    use crate::tests::{Identity, issue, issue_with};
    use openssl::{
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        pkey::{PKey, Private},
        rsa::Rsa,
        ssl::SslConnector,
    };
    use std::{
        collections::BTreeSet,
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };

    const VERSIONS: [SslVersion; 4] = [
        SslVersion::TLS1,
        SslVersion::TLS1_1,
        SslVersion::TLS1_2,
        SslVersion::TLS1_3,
    ];
    /// Every TLS 1.3 suite OpenSSL implements.
    const TLS13_ALL: [&str; 5] = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256",
    ];
    /// Group names OpenSSL 3.0-3.5 can implement. A name the linked client
    /// does not know cannot be offered and is skipped.
    const GROUPS_ALL: [&str; 19] = [
        "x25519",
        "x448",
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "ffdhe2048",
        "ffdhe3072",
        "ffdhe4096",
        "ffdhe6144",
        "ffdhe8192",
        "brainpoolP256r1tls13",
        "brainpoolP384r1tls13",
        "brainpoolP512r1tls13",
        "X25519MLKEM768",
        "SecP256r1MLKEM768",
        "SecP384r1MLKEM1024",
        "MLKEM512",
        "MLKEM768",
        "MLKEM1024",
    ];
    /// Everything the client library implements below TLS 1.3.
    const ALL_TLS12: &str = "ALL:COMPLEMENTOFALL";

    fn rsa(bits: u32) -> PKey<Private> {
        PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
    }
    fn ec(curve: Nid) -> PKey<Private> {
        PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(curve).unwrap()).unwrap())
            .unwrap()
    }

    struct Pki {
        dir: tempfile::TempDir,
        ca: Identity,
        client: Identity,
    }
    impl Pki {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let ca = issue("profile test ca", None, "ca");
            let client = issue("client", Some(&ca), "client");
            fs::write(dir.path().join("ca.pem"), ca.cert.to_pem().unwrap()).unwrap();
            Pki { dir, ca, client }
        }
        /// Writes a server identity with `key` and returns its name.
        fn server<'n>(&self, name: &'n str, key: PKey<Private>) -> &'n str {
            let id = issue_with(
                "localhost",
                Some(&self.ca),
                "server",
                key,
                MessageDigest::sha256(),
            );
            let d = self.dir.path();
            fs::write(d.join(format!("{name}.pem")), id.cert.to_pem().unwrap()).unwrap();
            fs::write(
                d.join(format!("{name}.key")),
                id.key.private_key_to_pem_pkcs8().unwrap(),
            )
            .unwrap();
            name
        }
        fn path(&self, file: &str) -> PathBuf {
            self.dir.path().join(file)
        }
        fn acceptor(&self, server: &str, profile: TlsProfile) -> Result<Arc<SslAcceptor>> {
            crate::tls(
                &self.path(&format!("{server}.pem")),
                &self.path(&format!("{server}.key")),
                &self.path("ca.pem"),
                None,
                profile,
            )
            .map(Arc::new)
        }
    }

    /// What the client offers. Unset fields offer everything the client
    /// implements; the client runs at security level 0 so that only the
    /// server's policy decides.
    #[derive(Clone, Copy)]
    struct Offer<'a> {
        version: SslVersion,
        tls12: Option<&'a str>,
        tls13: Option<&'a str>,
        groups: Option<&'a str>,
        sigalgs: Option<&'a str>,
        identity: Option<&'a Identity>,
    }
    fn offer(version: SslVersion) -> Offer<'static> {
        Offer {
            version,
            tls12: None,
            tls13: None,
            groups: None,
            sigalgs: None,
            identity: None,
        }
    }
    #[derive(Debug)]
    struct Session {
        version: SslVersion,
        suite: String,
        /// Server ephemeral key type: x25519, an EC curve, or None.
        group: Option<String>,
    }

    /// One mutually authenticated connection. Ok only when the server
    /// completed the handshake and the client received its application reply.
    fn connect(pki: &Pki, acceptor: &Arc<SslAcceptor>, o: Offer) -> Result<Session, String> {
        let mut b = SslConnector::builder(SslMethod::tls_client()).map_err(|e| e.to_string())?;
        b.set_security_level(0);
        b.set_ca_file(pki.path("ca.pem")).unwrap();
        let identity = o.identity.unwrap_or(&pki.client);
        b.set_certificate(&identity.cert).unwrap();
        b.set_private_key(&identity.key).unwrap();
        b.set_min_proto_version(Some(o.version)).unwrap();
        b.set_max_proto_version(Some(o.version)).unwrap();
        b.set_cipher_list(&format!("{}:@SECLEVEL=0", o.tls12.unwrap_or(ALL_TLS12)))
            .map_err(|e| format!("client cannot offer {:?}: {e}", o.tls12))?;
        b.set_ciphersuites(o.tls13.unwrap_or(&TLS13_ALL.join(":")))
            .map_err(|e| format!("client cannot offer {:?}: {e}", o.tls13))?;
        if let Some(g) = o.groups {
            b.set_groups_list(g)
                .map_err(|e| format!("client cannot offer {g}: {e}"))?;
        }
        if let Some(s) = o.sigalgs {
            b.set_sigalgs_list(s).unwrap();
        } else if let Ok(k) = identity.key.ec_key() {
            // An EC client signs CertificateVerify as ECDSA-256 (P-256,
            // SHA-256) or ECDSA-384 (P-384, SHA-384), as Profiles 1.3/1.4
            // 5.13 defines them: its own curve's hash comes first, and the
            // client's order decides its choice.
            let list = match k.group().curve_name() {
                Some(Nid::SECP384R1) => "ECDSA+SHA384:ECDSA+SHA256",
                _ => "ECDSA+SHA256:ECDSA+SHA384",
            };
            b.set_sigalgs_list(list).unwrap();
            b.set_options(openssl::ssl::SslOptions::CIPHER_SERVER_PREFERENCE);
        }
        let connector = b.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = acceptor.clone();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            match acceptor.accept(socket) {
                Ok(mut s) => {
                    let _ = s.write_all(b"ok");
                    let _ = s.flush();
                    let mut b = [0; 1];
                    let _ = s.read(&mut b);
                    let cipher = s.ssl().current_cipher().unwrap();
                    Ok(Session {
                        version: s.ssl().version2().unwrap(),
                        suite: cipher.standard_name().unwrap_or(cipher.name()).to_owned(),
                        group: None,
                    })
                }
                Err(e) => Err(e.to_string()),
            }
        });
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        // The server's ephemeral key as the client saw it (classical groups only).
        let mut group = None;
        let replied = match connector.connect("localhost", socket) {
            Ok(mut s) => {
                group = s.ssl().peer_tmp_key().ok().and_then(|k| match k.id() {
                    Id::EC => k
                        .ec_key()
                        .ok()?
                        .group()
                        .curve_name()
                        .and_then(|n| n.short_name().ok())
                        .map(str::to_owned),
                    Id::X25519 => Some("x25519".into()),
                    _ => None,
                });
                let mut b = [0; 2];
                let ok = s.read_exact(&mut b).is_ok() && &b == b"ok";
                let _ = s.write_all(b"x");
                ok
            }
            Err(_) => false,
        };
        let server = server.join().unwrap();
        match server {
            Ok(session) if replied => Ok(Session { group, ..session }),
            Ok(session) => Err(format!(
                "server completed {session:?} but the client got no reply"
            )),
            Err(e) => Err(e),
        }
    }

    fn policy(profile: TlsProfile) -> &'static Policy {
        profile.policy().unwrap()
    }

    /// TLS 1.2 suites with an HMAC-SHA1 CBC record layer also run on TLS 1.0/1.1.
    fn valid_below_tls12(s: &Suite) -> bool {
        s.iana.ends_with("_CBC_SHA")
    }

    /// The exhaustive check of one policy on one server credential.
    fn check(pki: &Pki, server: &str, profile: TlsProfile) {
        check_with(pki, server, profile, true)
    }
    fn check_with(pki: &Pki, server: &str, profile: TlsProfile, groups: bool) {
        let p = policy(profile);
        let acceptor = pki.acceptor(server, profile).unwrap();
        let listed12: BTreeSet<_> = p.tls12_suites.iter().map(|s| s.iana).collect();
        let listed13: BTreeSet<_> = p.tls13_suites.iter().copied().collect();
        // Versions: offering everything at one version negotiates exactly the
        // policy's versions, always with a listed suite.
        for v in VERSIONS {
            let r = connect(pki, &acceptor, offer(v));
            if p.versions.contains(&v) {
                let s = r.unwrap_or_else(|e| panic!("{} {}: {e}", p.name, version_name(v)));
                assert_eq!(s.version, v);
                assert!(
                    listed12.contains(s.suite.as_str()) || listed13.contains(s.suite.as_str()),
                    "{} negotiated unlisted {}",
                    p.name,
                    s.suite
                );
            } else {
                assert!(
                    r.is_err(),
                    "{} accepted unlisted {}",
                    p.name,
                    version_name(v)
                );
            }
        }
        // Each listed TLS 1.0-1.2 suite alone negotiates at each version it is defined for.
        for s in p.tls12_suites {
            for &v in p.versions.iter().filter(|v| **v != SslVersion::TLS1_3) {
                let r = connect(
                    pki,
                    &acceptor,
                    Offer {
                        tls12: Some(s.openssl),
                        ..offer(v)
                    },
                );
                if v == SslVersion::TLS1_2 || valid_below_tls12(s) {
                    let session =
                        r.unwrap_or_else(|e| panic!("{} {}: {e}", s.iana, version_name(v)));
                    assert_eq!((session.version, session.suite.as_str()), (v, s.iana));
                } else {
                    assert!(
                        r.is_err(),
                        "{} is not defined for {}",
                        s.iana,
                        version_name(v)
                    );
                }
            }
        }
        // Closure: offering every other suite the client implements is refused
        // at every version, so no unlisted suite can be negotiated.
        let excluded: String = p
            .tls12_suites
            .iter()
            .map(|s| format!(":!{}", s.openssl))
            .collect();
        for v in &VERSIONS[..3] {
            let all_others = format!("{ALL_TLS12}{excluded}");
            let r = connect(
                pki,
                &acceptor,
                Offer {
                    tls12: Some(&all_others),
                    ..offer(*v)
                },
            );
            assert!(
                r.is_err(),
                "{} {}: unlisted suite negotiated: {r:?}",
                p.name,
                version_name(*v)
            );
        }
        // TLS 1.3: each suite alone negotiates iff listed.
        for s in TLS13_ALL {
            let r = connect(
                pki,
                &acceptor,
                Offer {
                    tls13: Some(s),
                    ..offer(SslVersion::TLS1_3)
                },
            );
            if listed13.contains(s) {
                assert_eq!(r.unwrap().suite, s);
            } else {
                assert!(r.is_err(), "{} accepted unlisted {s}", p.name);
            }
        }
        if groups && !p.groups.is_empty() {
            check_groups(pki, &acceptor, p);
        }
    }

    /// Each group alone: negotiates iff listed (TLS 1.3 and TLS 1.2 ECDHE-RSA).
    fn check_groups(pki: &Pki, acceptor: &Arc<SslAcceptor>, p: &Policy) {
        let ecdhe_rsa = p
            .tls12_suites
            .iter()
            .filter(|s| s.iana.starts_with("TLS_ECDHE_RSA"))
            .map(|s| s.openssl)
            .collect::<Vec<_>>()
            .join(":");
        let mut offered = 0;
        for g in GROUPS_ALL {
            let mut attempts = vec![];
            if p.versions.contains(&SslVersion::TLS1_3) {
                attempts.push(Offer {
                    groups: Some(g),
                    ..offer(SslVersion::TLS1_3)
                });
            }
            if !ecdhe_rsa.is_empty() {
                attempts.push(Offer {
                    groups: Some(g),
                    tls12: Some(&ecdhe_rsa),
                    ..offer(SslVersion::TLS1_2)
                });
            }
            for o in attempts {
                // TLS 1.2 ECDHE uses only elliptic-curve groups.
                let usable = o.version == SslVersion::TLS1_3
                    || !g.starts_with("ffdhe") && !g.contains("MLKEM");
                match connect(pki, acceptor, o) {
                    Err(e) if e.starts_with("client cannot offer") => continue,
                    Ok(s) => {
                        assert!(
                            p.groups.contains(&g) && usable,
                            "{} accepted unlisted group {g}",
                            p.name
                        );
                        if let Some(group) = s.group {
                            let expected = match g {
                                "secp256r1" => "prime256v1",
                                other => other,
                            };
                            assert_eq!(group, expected, "{} {g}", p.name);
                        }
                    }
                    Err(e) => assert!(
                        !(p.groups.contains(&g) && usable),
                        "{} refused listed group {g}: {e}",
                        p.name
                    ),
                }
                offered += 1;
            }
        }
        assert!(offered > 0);
    }

    // REQ:f21e65afd4502c15 2.0-3.0 Basic (closed list): no suite outside 3.1.2 negotiates under kmip-2-basic
    // REQ:0e66a8dd9875b28d 2.0-3.0 HTTPS protocols follow Basic 3.1.1; the HTTPS listener uses the same acceptor (main.rs)
    // REQ:9c674512b974d5dd 2.0-3.0 HTTPS cipher suites follow Basic 3.1.2; the HTTPS listener uses the same acceptor
    // REQ:cb9986eebbf0354a 2.0/2.1 profiles support the Basic Authentication Suite (3.1) under --tls-profile kmip-2-basic;
    //   mutual TLS, Credential client authenticity and the port are cited in main.rs and tests/header_credentials.rs
    // REQ:5fd33956ec89a14f 2.0/2.1 HTTPS profiles support the HTTPS Authentication Suite (3.2) under kmip-2-basic (same acceptor)
    #[test]
    fn kmip_2_basic_negotiates_exactly_tls_1_3_with_the_two_listed_suites() {
        let pki = Pki::new();
        let rsa_server = pki.server("rsa", rsa(2048));
        let ec_server = pki.server("ec", ec(Nid::X9_62_PRIME256V1));
        for server in [rsa_server, ec_server] {
            check(&pki, server, TlsProfile::Kmip2Basic);
        }
    }

    // REQ:5f9a61b3955ed555 2.0-3.0 Basic: with TLS 1.2 supported, both mandatory static-RSA suites negotiate
    // REQ:f21e65afd4502c15 2.0-3.0 Basic (closed list): only listed TLS 1.2 and TLS 1.3 suites negotiate
    // REQ:9c674512b974d5dd 2.0-3.0 HTTPS cipher suites follow Basic 3.1.2 (same acceptor)
    #[test]
    fn kmip_2_basic_tls12_adds_the_mandatory_static_rsa_suites_and_nothing_unlisted() {
        let pki = Pki::new();
        let server = pki.server("rsa", rsa(2048));
        check(&pki, server, TlsProfile::Kmip2BasicTls12);
        // ECDHE-RSA is preferred when the client offers it.
        let acceptor = pki.acceptor(server, TlsProfile::Kmip2BasicTls12).unwrap();
        let s = connect(&pki, &acceptor, offer(SslVersion::TLS1_2)).unwrap();
        assert_eq!(s.suite, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
    }

    // REQ:cbff2711cd6583de 1.1-1.4 TLS 1.2 suite: TLS_RSA_WITH_AES_{256,128}_CBC_SHA256 negotiate
    // REQ:1c7aea29c89fd491 1.4 Basic: TLS_RSA_WITH_AES_{256,128}_CBC_SHA256 negotiate
    // REQ:eaaf67287b354f22 1.4 Basic: TLS 1.2 is supported (TLS 1.0 is refused, per its SHALL NOT)
    // REQ:4326643c3df4e727 1.1 TLS 1.2 suite: no other cipher suite negotiates
    // REQ:f21e65afd4502c15 1.4 Basic (closed list): no unlisted suite negotiates
    // REQ:2636d511bbce910b 1.3/1.4 TLS 1.2 suite: only TLS 1.2 is negotiated (TLS 1.3, 1.1 and 1.0 are refused)
    // REQ:0e66a8dd9875b28d 1.4 HTTPS protocols follow 1.4 Basic 3.1.1 (same acceptor)
    // REQ:9c674512b974d5dd 1.4 HTTPS cipher suites follow 1.4 Basic 3.1.2 (same acceptor)
    // REQ:84bd6ddaef6565f2 1.3/1.4 profiles support the TLS 1.2 Authentication Suite (3.2) under --tls-profile kmip-1-tls12
    // REQ:cb9986eebbf0354a 1.4 profiles support the 1.4 Basic Authentication Suite (3.1) under --tls-profile kmip-1-tls12
    // REQ:697cbd666309c2d2 1.4 HTTPS profile supports the HTTPS Authentication Suite (3.5) under kmip-1-tls12 (same acceptor)
    //   (mutual TLS, Credential client authenticity and the port are cited in main.rs and tests/header_credentials.rs)
    #[test]
    fn kmip_1_tls12_negotiates_only_tls_1_2_with_the_mandatory_suites() {
        let pki = Pki::new();
        let server = pki.server("rsa", rsa(2048));
        check(&pki, server, TlsProfile::Kmip1Tls12);
    }

    // REQ:68cc913e455f927d 1.1 Basic: TLS 1.0 is supported
    // REQ:eaaf67287b354f22 1.2/1.3 Basic: TLS 1.0 is supported (with the MAY TLS 1.1 and the 1.3 SHOULD TLS 1.2)
    // REQ:cbff2711cd6583de 1.1 Basic: TLS_RSA_WITH_AES_128_CBC_SHA negotiates
    // REQ:1c7aea29c89fd491 1.2/1.3 Basic: TLS_RSA_WITH_AES_128_CBC_SHA negotiates
    // REQ:5d8d0bd7763246d6 1.1 Basic: no other cipher suite negotiates
    // REQ:f21e65afd4502c15 1.2/1.3 Basic (closed list): no unlisted suite negotiates; TLS 1.3 (no listed suite) is refused
    // REQ:0e66a8dd9875b28d 1.3 HTTPS protocols follow 1.3 Basic 3.1.1 (same acceptor)
    // REQ:9c674512b974d5dd 1.3 HTTPS cipher suites follow 1.3 Basic 3.1.2 (same acceptor)
    // REQ:cb9986eebbf0354a 1.3 profiles support the 1.3 Basic Authentication Suite (3.1) under --tls-profile kmip-1-basic
    // REQ:697cbd666309c2d2 1.3 HTTPS profile supports the HTTPS Authentication Suite (3.5) under kmip-1-basic (same acceptor)
    //   (mutual TLS, Credential client authenticity and the port are cited in main.rs and tests/header_credentials.rs)
    #[test]
    fn kmip_1_basic_negotiates_tls_1_0_to_1_2_with_the_mandatory_suite() {
        let pki = Pki::new();
        let server = pki.server("rsa", rsa(2048));
        check(&pki, server, TlsProfile::Kmip1Basic);
    }

    /// Security level 0 is needed for TLS 1.0/1.1; certificate keys, chain
    /// signatures and TLS 1.2 signature algorithms still meet level 2.
    #[test]
    fn kmip_1_basic_still_refuses_weak_peer_credentials() {
        let pki = Pki::new();
        let server = pki.server("rsa", rsa(2048));
        let acceptor = pki.acceptor(server, TlsProfile::Kmip1Basic).unwrap();
        let small = issue_with(
            "small",
            Some(&pki.ca),
            "client",
            rsa(1024),
            MessageDigest::sha256(),
        );
        let sha1 = issue_with(
            "sha1",
            Some(&pki.ca),
            "client",
            rsa(2048),
            MessageDigest::sha1(),
        );
        for v in [SslVersion::TLS1, SslVersion::TLS1_2] {
            assert!(connect(&pki, &acceptor, offer(v)).is_ok());
            for id in [&small, &sha1] {
                let r = connect(
                    &pki,
                    &acceptor,
                    Offer {
                        identity: Some(id),
                        ..offer(v)
                    },
                );
                assert!(r.is_err(), "{}: weak client accepted", version_name(v));
            }
        }
        let r = connect(
            &pki,
            &acceptor,
            Offer {
                sigalgs: Some("RSA+SHA1"),
                ..offer(SslVersion::TLS1_2)
            },
        );
        assert!(r.is_err(), "SHA-1 CertificateVerify accepted");
        // A weak server credential is refused at startup.
        let weak = pki.server("weak", rsa(1024));
        let error = pki.acceptor(weak, TlsProfile::Kmip1Basic).err().unwrap();
        // OpenSSL refuses it while loading at the default level; the policy's
        // own check would refuse it otherwise.
        let error = format!("{error:#}");
        assert!(
            error.contains("below 112") || error.contains("key too small"),
            "{error}"
        );
    }

    /// A Suite B PKI: a P-384 CA signing with SHA-384 (RFC 6460 chains) and
    /// a client on `curve`.
    fn suite_b_pki(curve: Nid) -> Pki {
        let dir = tempfile::tempdir().unwrap();
        let ca = issue_with(
            "suite b ca",
            None,
            "ca",
            ec(Nid::SECP384R1),
            MessageDigest::sha384(),
        );
        let client = issue_with(
            "client",
            Some(&ca),
            "client",
            ec(curve),
            MessageDigest::sha384(),
        );
        fs::write(dir.path().join("ca.pem"), ca.cert.to_pem().unwrap()).unwrap();
        Pki { dir, ca, client }
    }
    impl Pki {
        /// An end entity of this CA with `key`, signed with SHA-384.
        fn suite_b_identity(&self, name: &str, usage: &str, key: PKey<Private>) -> Identity {
            issue_with(name, Some(&self.ca), usage, key, MessageDigest::sha384())
        }
        fn suite_b_server<'n>(&self, name: &'n str, curve: Nid) -> &'n str {
            let id = self.suite_b_identity("localhost", "server", ec(curve));
            self.write_server(name, &id)
        }
        fn write_server<'n>(&self, name: &'n str, id: &Identity) -> &'n str {
            let d = self.dir.path();
            fs::write(d.join(format!("{name}.pem")), id.cert.to_pem().unwrap()).unwrap();
            fs::write(
                d.join(format!("{name}.key")),
                id.key.private_key_to_pem_pkcs8().unwrap(),
            )
            .unwrap();
            name
        }
    }
    /// An EC certificate of `pki`'s CA with the given key usage extension
    /// (None: no key usage extension).
    fn ec_with_usage(
        pki: &Pki,
        curve: Nid,
        usage: Option<openssl::x509::extension::KeyUsage>,
    ) -> Identity {
        let key = ec(curve);
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(
            &openssl::bn::BigNum::from_u32(7)
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(pki.ca.cert.subject_name()).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        if let Some(mut usage) = usage {
            b.append_extension(usage.critical().build().unwrap())
                .unwrap();
        }
        b.sign(&pki.ca.key, MessageDigest::sha384()).unwrap();
        Identity {
            cert: b.build(),
            key,
        }
    }
    fn key_agreement_only() -> openssl::x509::extension::KeyUsage {
        let mut u = openssl::x509::extension::KeyUsage::new();
        u.key_agreement();
        u
    }
    const AES128: &str = "ECDHE-ECDSA-AES128-GCM-SHA256";
    const AES256: &str = "ECDHE-ECDSA-AES256-GCM-SHA384";
    fn suite_b_offer<'a>(suite: &'a str, groups: &'a str) -> Offer<'a> {
        Offer {
            tls12: Some(suite),
            groups: Some(groups),
            ..offer(SslVersion::TLS1_2)
        }
    }
    fn with_identity<'a>(id: &'a Identity, suite: &'a str, groups: &'a str) -> Offer<'a> {
        Offer {
            identity: Some(id),
            ..suite_b_offer(suite, groups)
        }
    }
    /// The level's PKI: its curve for the server and the client.
    fn level(profile: TlsProfile) -> (Pki, Nid, &'static str, &'static str) {
        let (curve, suite, group) = if profile == TlsProfile::Kmip1SuiteB192 {
            (Nid::SECP384R1, AES256, "secp384r1")
        } else {
            (Nid::X9_62_PRIME256V1, AES128, "secp256r1")
        };
        (suite_b_pki(curve), curve, suite, group)
    }

    // REQ:cbff2711cd6583de 1.3/1.4 Suite B minLOS_128 (AES-128-GCM) and minLOS_192 (AES-256-GCM) mandatory suites negotiate
    // REQ:6c5bdfb717dc4159 1.3/1.4 Suite B minLOS_128 Authentication Suite (3.3): TLS 1.2 and its suite under --tls-profile kmip-1-suite-b-128
    // REQ:d1c95ee5bed80900 1.3/1.4 Suite B minLOS_192 Authentication Suite (3.4): TLS 1.2 and its suite under --tls-profile kmip-1-suite-b-192
    //   (mutual TLS, client authenticity per 3.2.3 and the port are cited in main.rs and tests/header_credentials.rs)
    #[test]
    fn kmip_1_suite_b_levels_negotiate_tls_1_2_with_their_suites_only() {
        for profile in [TlsProfile::Kmip1SuiteB128, TlsProfile::Kmip1SuiteB192] {
            let (pki, curve, ..) = level(profile);
            let server = pki.suite_b_server("server", curve);
            // Versions, suites and suite closure as for every policy.
            check_with(&pki, server, profile, false);
        }
    }

    // REQ:f27f80565082a1cb minLOS_128: the non-signature primitives all come from column 1 (AES-128, P-256 ECDHE, SHA-256)
    // REQ:8edf54cb1706f1fd minLOS_192: the non-signature primitives all come from column 2 (AES-256, P-384 ECDHE, SHA-384)
    #[test]
    fn suite_b_primitives_come_from_one_column() {
        for profile in [TlsProfile::Kmip1SuiteB128, TlsProfile::Kmip1SuiteB192] {
            let (pki, curve, suite, group) = level(profile);
            let server = pki.suite_b_server("server", curve);
            let acceptor = pki.acceptor(server, profile).unwrap();
            let expected = if group == "secp256r1" {
                "prime256v1"
            } else {
                group
            };
            // The column's suite with every group offered, either order:
            // the column's group is used.
            let both = ["secp256r1:secp384r1", "secp384r1:secp256r1"];
            for groups in both {
                let s = connect(&pki, &acceptor, suite_b_offer(suite, groups))
                    .unwrap_or_else(|e| panic!("{profile:?} {groups}: {e}"));
                assert_eq!(s.group.as_deref(), Some(expected), "{profile:?}");
            }
            // The other column's suite with this column's group: the
            // modern policy mixes them, the Suite B policy refuses.
            let other = if suite == AES128 { AES256 } else { AES128 };
            let modern = pki.acceptor(server, TlsProfile::Modern).unwrap();
            connect(&pki, &modern, suite_b_offer(other, group)).unwrap();
            assert!(connect(&pki, &acceptor, suite_b_offer(other, group)).is_err());
            // This column's suite with every other group alone is refused.
            for g in GROUPS_ALL.iter().filter(|g| **g != group) {
                match connect(&pki, &acceptor, suite_b_offer(suite, g)) {
                    Err(e) if e.starts_with("client cannot offer") => {}
                    r => assert!(r.is_err(), "{profile:?} negotiated {g}"),
                }
            }
        }
    }

    // REQ:99adaf22b0951db9 both sides authenticate with ECDSA: RSA client certificates are refused under Suite B
    // REQ:d7c1728623ee5f31 minLOS_192: the client and the server authenticate with ECDSA-384 (P-256 is refused on either side)
    // REQ:1a10869fd96cd3dc each certificate is X.509 v3 with an EC key and the digitalSignature key usage; chains follow
    //   OpenSSL's RFC 6460 Suite B rules (the complete RFC 5759 profile is not pinned and not checked)
    /// `--ec-curves` does not change TLS: a
    /// server certificate on a non-NIST implemented curve is still accepted
    /// at startup. Measured for the open image finding (CVE-2026-54872,
    /// OpenSSL's generic-curve ECDSA): the default `modern` policy never
    /// signs a handshake with such a key. TLS 1.2 finds no shared cipher (the
    /// policy's groups are P-256, P-384 and P-521) and TLS 1.3 has no
    /// signature scheme for it (the policy lists no brainpool scheme, and
    /// secp256k1 has none). Only the non-default `mozilla-intermediate`
    /// policy signs a TLS 1.3 CertificateVerify with a brainpool key.
    #[test]
    fn non_nist_server_certificates_never_sign_under_the_default_policy() {
        let pki = Pki::new();
        for (name, nid, group) in [
            ("bp256", Nid::BRAINPOOL_P256R1, "brainpoolP256r1"),
            ("k256", Nid::SECP256K1, "secp256k1"),
        ] {
            let tls12 = Offer {
                groups: Some(group),
                ..offer(SslVersion::TLS1_2)
            };
            let tls13 = Offer {
                groups: Some("brainpoolP256r1tls13:secp256r1"),
                ..offer(SslVersion::TLS1_3)
            };
            let name = pki.server(name, ec(nid));
            let modern = pki.acceptor(name, TlsProfile::Modern).unwrap();
            assert!(connect(&pki, &modern, tls12).is_err(), "{name}");
            let tls13_nist = Offer {
                groups: Some("secp256r1"),
                ..tls13
            };
            assert!(connect(&pki, &modern, tls13_nist).is_err(), "{name}");
            let intermediate = pki.acceptor(name, TlsProfile::MozillaIntermediate).unwrap();
            assert!(connect(&pki, &intermediate, tls12).is_err(), "{name}");
            assert_eq!(
                connect(&pki, &intermediate, tls13).is_ok(),
                nid == Nid::BRAINPOOL_P256R1,
                "{name}"
            );
        }
    }

    /// Server and peer certificates on a curve the server does not support
    /// are refused (docs/interpretations.md), before OpenSSL loads them.
    #[test]
    fn certificates_on_removed_curves_are_refused_by_every_listener() {
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../tests/ec-removed-curves.json")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        for (name, fixture) in data["curves"].as_object().unwrap() {
            let der = |field: &str| hex::decode(fixture[field].as_str().unwrap()).unwrap();
            let pem = |label: &str, der: &[u8]| {
                format!(
                    "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
                    openssl::base64::encode_block(der)
                )
            };
            let cert = X509::from_der(&der("certificate")).unwrap();
            assert!(!supported_curve(&cert), "{name}");
            let (cert_path, key_path) = (
                dir.path().join(format!("{name}.pem")),
                dir.path().join(format!("{name}.key")),
            );
            fs::write(&cert_path, pem("CERTIFICATE", &der("certificate"))).unwrap();
            fs::write(&key_path, pem("PRIVATE KEY", &der("pkcs8"))).unwrap();
            let error = crate::tls(&cert_path, &key_path, &cert_path, None, TlsProfile::Modern)
                .err()
                .unwrap_or_else(|| panic!("{name}: the listener started"));
            assert!(
                error.to_string().contains("unsupported curve"),
                "{name}: {error}"
            );
        }
        // TLS keeps all 13 implemented curves whatever `--ec-curves` says
        // (only KMIP operations follow it): the thread-local setting is `nist`
        // here, and secp256k1 and brainpool certificates still pass.
        assert_eq!(
            keytend_kmip_server::crypto::ec::active(),
            keytend_kmip_server::crypto::ec::EcCurves::Nist
        );
        for nid in [
            Nid::X9_62_PRIME256V1,
            Nid::SECP256K1,
            Nid::BRAINPOOL_P256R1,
            Nid::BRAINPOOL_P512R1,
        ] {
            let key = PKey::from_ec_key(
                EcKey::generate(&EcGroup::from_curve_name(nid).unwrap()).unwrap(),
            )
            .unwrap();
            let mut builder = openssl::x509::X509Builder::new().unwrap();
            builder.set_pubkey(&key).unwrap();
            builder.sign(&key, MessageDigest::sha256()).unwrap();
            assert!(supported_curve(&builder.build()), "{nid:?}");
        }
    }

    #[test]
    fn suite_b_authentication_is_ecdsa_with_digital_signature_certificates() {
        for profile in [TlsProfile::Kmip1SuiteB128, TlsProfile::Kmip1SuiteB192] {
            let (pki, curve, suite, _) = level(profile);
            let server = pki.suite_b_server("server", curve);
            let other_curve = if curve == Nid::SECP384R1 {
                Nid::X9_62_PRIME256V1
            } else {
                Nid::SECP384R1
            };
            let rsa_client = pki.suite_b_identity("rsa client", "client", rsa(2048));
            let other_client = pki.suite_b_identity("other client", "client", ec(other_curve));
            let no_usage = ec_with_usage(&pki, curve, None);
            let agreement_only = ec_with_usage(&pki, curve, Some(key_agreement_only()));
            // The modern policy accepts each of these clients, so the
            // refusals below come from the Suite B policy.
            let modern = pki.acceptor(server, TlsProfile::Modern).unwrap();
            let all_groups = "secp256r1:secp384r1";
            for id in [&rsa_client, &other_client, &no_usage, &agreement_only] {
                connect(&pki, &modern, with_identity(id, suite, all_groups)).unwrap();
            }
            let acceptor = pki.acceptor(server, profile).unwrap();
            connect(&pki, &acceptor, suite_b_offer(suite, all_groups)).unwrap();
            for id in [&rsa_client, &other_client, &no_usage, &agreement_only] {
                assert!(
                    connect(&pki, &acceptor, with_identity(id, suite, all_groups)).is_err(),
                    "{profile:?} accepted {:?}",
                    id.cert.subject_name()
                );
            }
            // Server credentials: the other curve, RSA, P-521, or an EC
            // certificate without digitalSignature, are refused at startup.
            let wrong_curve = pki.suite_b_server("wrong", other_curve);
            let rsa_server = pki.write_server(
                "rsa",
                &pki.suite_b_identity("localhost", "server", rsa(2048)),
            );
            let p521 = pki.suite_b_server("p521", Nid::SECP521R1);
            let unusable = pki.write_server(
                "unusable",
                &ec_with_usage(&pki, curve, Some(key_agreement_only())),
            );
            let bare = pki.write_server("bare", &ec_with_usage(&pki, curve, None));
            for server in [wrong_curve, rsa_server, p521, unusable, bare] {
                let error = format!("{:#}", pki.acceptor(server, profile).err().unwrap());
                assert!(error.contains("server certificate"), "{profile:?}: {error}");
            }
        }
    }

    // REQ:99adaf22b0951db9 1.3/1.4 Suite B: certificates are signed with ECDSA-256 or ECDSA-384 (5.13)
    /// A server certificate whose own signature Suite B mode cannot accept
    /// (an RSA issuer, or the wrong hash for a P-384 issuer) is refused at
    /// startup instead of starting a listener that negotiates nothing. Each
    /// such certificate starts under `modern`.
    #[test]
    fn suite_b_refuses_a_server_certificate_signed_outside_suite_b() {
        let rsa_ca = issue_with("rsa ca", None, "ca", rsa(2048), MessageDigest::sha256());
        let p256_ca = issue_with(
            "p256 ca",
            None,
            "ca",
            ec(Nid::X9_62_PRIME256V1),
            MessageDigest::sha256(),
        );
        for profile in [TlsProfile::Kmip1SuiteB128, TlsProfile::Kmip1SuiteB192] {
            let (pki, curve, suite, group) = level(profile);
            let issued = |name, ca: &Identity, digest| {
                pki.write_server(
                    name,
                    &issue_with("localhost", Some(ca), "server", ec(curve), digest),
                )
            };
            let by_rsa = issued("by-rsa", &rsa_ca, MessageDigest::sha256());
            // The level's CA (P-384) signing with SHA-256 or SHA-512.
            let sha256 = issued("sha256", &pki.ca, MessageDigest::sha256());
            let sha512 = issued("sha512", &pki.ca, MessageDigest::sha512());
            // minLOS_128 allows ECDSA-256 signatures. Whether the issuer of a
            // SHA-256 signature is a P-256 key is left to the handshake: the
            // issuer need not be at hand when the listener starts.
            let refused = if profile == TlsProfile::Kmip1SuiteB192 {
                vec![by_rsa, sha256, sha512]
            } else {
                vec![by_rsa, sha512]
            };
            for server in refused {
                pki.acceptor(server, TlsProfile::Modern).unwrap();
                let error = format!("{:#}", pki.acceptor(server, profile).err().unwrap());
                assert!(
                    error.contains("server certificate is signed with"),
                    "{profile:?}: {error}"
                );
            }
            // ECDSA-256 (a P-256 issuer with SHA-256) is allowed at
            // minLOS_128 only.
            let by_p256 = issued("by-p256", &p256_ca, MessageDigest::sha256());
            let built = pki.acceptor(by_p256, profile);
            assert_eq!(
                built.is_ok(),
                profile == TlsProfile::Kmip1SuiteB128,
                "{profile:?}"
            );
            // The level's own chain still starts and negotiates.
            let good = pki.suite_b_server("good", curve);
            let acceptor = pki.acceptor(good, profile).unwrap();
            connect(&pki, &acceptor, suite_b_offer(suite, group)).unwrap();
        }
    }

    /// The default `modern` policy negotiates only approved suites, groups
    /// and signatures (docs/fips.md); `mozilla-intermediate` keeps the
    /// ChaCha20-Poly1305 suites and X25519 that the default dropped.
    #[test]
    fn modern_is_fips_approved_and_mozilla_intermediate_is_not() {
        let pki = Pki::new();
        let rsa_server = pki.server("rsa", rsa(2048));
        let ec_server = pki.server("ec", ec(Nid::X9_62_PRIME256V1));
        for server in [rsa_server, ec_server] {
            let modern = pki.acceptor(server, TlsProfile::Modern).unwrap();
            let mozilla = pki
                .acceptor(server, TlsProfile::MozillaIntermediate)
                .unwrap();
            for suite in ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"] {
                let s = connect(
                    &pki,
                    &modern,
                    Offer {
                        tls13: Some(suite),
                        ..offer(SslVersion::TLS1_3)
                    },
                )
                .unwrap_or_else(|e| panic!("{suite}: {e}"));
                assert_eq!(s.suite, suite);
            }
            let chacha = || Offer {
                tls13: Some("TLS_CHACHA20_POLY1305_SHA256"),
                ..offer(SslVersion::TLS1_3)
            };
            assert!(connect(&pki, &modern, chacha()).is_err());
            connect(&pki, &mozilla, chacha()).unwrap();
            let x25519 = || Offer {
                groups: Some("x25519"),
                ..offer(SslVersion::TLS1_3)
            };
            assert!(connect(&pki, &modern, x25519()).is_err());
            assert_eq!(
                connect(&pki, &mozilla, x25519()).unwrap().group.as_deref(),
                Some("x25519")
            );
            for (group, expected) in [("secp256r1", "prime256v1"), ("secp384r1", "secp384r1")] {
                let s = connect(
                    &pki,
                    &modern,
                    Offer {
                        groups: Some(group),
                        ..offer(SslVersion::TLS1_3)
                    },
                )
                .unwrap();
                assert_eq!(s.group.as_deref(), Some(expected));
            }
            let tls12_chacha = || Offer {
                tls12: Some("ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"),
                ..offer(SslVersion::TLS1_2)
            };
            assert!(connect(&pki, &modern, tls12_chacha()).is_err());
            connect(&pki, &mozilla, tls12_chacha()).unwrap();
            // No finite-field DHE in `modern` (CVE-2024-41996, docs/fips.md):
            // neither the TLS 1.3 FFDHE groups nor the TLS 1.2 DHE-RSA suites.
            for group in ["ffdhe2048", "ffdhe3072"] {
                let ffdhe = || Offer {
                    groups: Some(group),
                    ..offer(SslVersion::TLS1_3)
                };
                assert!(connect(&pki, &modern, ffdhe()).is_err(), "{group}");
                connect(&pki, &mozilla, ffdhe()).unwrap();
            }
            let dhe = || Offer {
                tls12: Some("DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"),
                ..offer(SslVersion::TLS1_2)
            };
            assert!(connect(&pki, &modern, dhe()).is_err());
            if server == rsa_server {
                connect(&pki, &mozilla, dhe()).unwrap();
            }
        }
    }

    #[test]
    fn fips_mode_starts_only_with_approved_profiles() {
        use clap::ValueEnum;
        let approved: Vec<_> = TlsProfile::value_variants()
            .iter()
            .filter(|p| p.fips_approved())
            .copied()
            .collect();
        assert_eq!(
            approved,
            [
                TlsProfile::Modern,
                TlsProfile::Kmip1SuiteB128,
                TlsProfile::Kmip1SuiteB192
            ]
        );
        for p in POLICIES {
            let profile = TlsProfile::from_str(p.name, false).unwrap();
            let approved_lists = p.tls13_suites.iter().all(|s| !s.contains("CHACHA"))
                && p.groups.iter().all(|g| g.starts_with("secp"))
                && p.tls12_suites
                    .iter()
                    .all(|s| s.iana.starts_with("TLS_ECDHE_"))
                && !p.versions.contains(&SslVersion::TLS1)
                && !p.versions.contains(&SslVersion::TLS1_1);
            assert_eq!(profile.fips_approved(), approved_lists, "{}", p.name);
        }
    }

    #[test]
    fn the_old_suite_b_value_selects_min_los_128() {
        use clap::ValueEnum;
        assert_eq!(
            TlsProfile::from_str("kmip-1-suite-b", false).unwrap(),
            TlsProfile::Kmip1SuiteB128
        );
    }

    // REQ:f21e65afd4502c15 3.0 CSD02 Quantum Safe (closed list): only the two listed TLS 1.3 suites negotiate
    #[test]
    fn kmip_3_quantum_safe_negotiates_only_the_hybrid_groups_on_tls_1_3() {
        let pki = Pki::new();
        let server = pki.server("rsa", rsa(2048));
        let built = pki.acceptor(server, TlsProfile::Kmip3QuantumSafe);
        // The hybrid ML-KEM groups first appear in OpenSSL 3.5.
        if openssl::version::number() < 0x3050_0000 {
            let error = format!("{:#}", built.err().expect("hybrid groups need OpenSSL 3.5"));
            assert!(error.contains("does not provide all of them"), "{error}");
            return;
        }
        check(&pki, server, TlsProfile::Kmip3QuantumSafe);
    }

    #[test]
    fn a_policy_refuses_a_server_certificate_that_cannot_serve_its_suites() {
        let pki = Pki::new();
        let rsa_server = pki.server("rsa", rsa(2048));
        let ec_server = pki.server("ec", ec(Nid::X9_62_PRIME256V1));
        let p521 = pki.server("p521", ec(Nid::SECP521R1));
        for (server, profile) in [
            (ec_server, TlsProfile::Kmip1Basic),
            (ec_server, TlsProfile::Kmip1Tls12),
            (ec_server, TlsProfile::Kmip2BasicTls12),
            (rsa_server, TlsProfile::Kmip1SuiteB128),
            (p521, TlsProfile::Kmip1SuiteB128),
            (ec_server, TlsProfile::Kmip1SuiteB192),
            (rsa_server, TlsProfile::Kmip1SuiteB192),
        ] {
            let error = format!("{:#}", pki.acceptor(server, profile).err().unwrap());
            assert!(error.contains("server certificate"), "{profile:?}: {error}");
        }
        for (server, profile) in [
            (rsa_server, TlsProfile::Modern),
            (ec_server, TlsProfile::Modern),
            (ec_server, TlsProfile::Kmip2Basic),
        ] {
            pki.acceptor(server, profile).unwrap();
        }
    }

    /// Exactly the policies with static RSA or TLS 1.0/1.1 warn, and only
    /// those lower the security level.
    #[test]
    fn legacy_policies_and_only_those_carry_a_warning() {
        for p in POLICIES {
            let legacy = p
                .tls12_suites
                .iter()
                .any(|s| s.iana.starts_with("TLS_RSA_"))
                || p.versions.contains(&SslVersion::TLS1)
                || p.versions.contains(&SslVersion::TLS1_1);
            assert_eq!(p.warning.is_some(), legacy, "{}", p.name);
            assert!(
                !p.security_level_0 || p.versions.contains(&SslVersion::TLS1),
                "{}",
                p.name
            );
            // Contiguous version ranges, with suites for each enabled family.
            let i = VERSIONS.iter().position(|v| *v == p.versions[0]).unwrap();
            assert_eq!(p.versions, &VERSIONS[i..i + p.versions.len()], "{}", p.name);
            assert_eq!(
                p.versions.contains(&SslVersion::TLS1_3),
                !p.tls13_suites.is_empty()
            );
            assert_eq!(
                p.versions[0] != SslVersion::TLS1_3,
                !p.tls12_suites.is_empty()
            );
        }
        let names: Vec<_> = POLICIES.iter().map(|p| p.name).collect();
        for profile in [
            TlsProfile::Kmip2Basic,
            TlsProfile::Kmip2BasicTls12,
            TlsProfile::Kmip1Tls12,
            TlsProfile::Kmip1Basic,
            TlsProfile::Kmip1SuiteB128,
            TlsProfile::Kmip1SuiteB192,
            TlsProfile::Kmip3QuantumSafe,
        ] {
            let name = clap::ValueEnum::to_possible_value(&profile).unwrap();
            assert_eq!(policy(profile).name, name.get_name());
            assert!(names.contains(&name.get_name()));
        }
        assert!(TlsProfile::Modern.policy().is_none());
        assert!(TlsProfile::MozillaIntermediate.policy().is_none());
    }

    #[test]
    fn serve_defaults_to_the_modern_policy() {
        use clap::Parser;
        let base = [
            "keytend-kmip-server",
            "serve",
            "--cert",
            "c",
            "--key",
            "k",
            "--ca",
            "a",
            "--policy",
            "p",
            "--master-key",
            "m",
        ];
        let profile = |extra: &[&str]| {
            let args = crate::Args::try_parse_from(base.iter().chain(extra)).unwrap();
            let crate::Command::Serve(options) = args.command else {
                panic!("expected serve")
            };
            options.tls_profile
        };
        assert_eq!(profile(&[]), TlsProfile::Modern);
        assert_eq!(
            profile(&["--tls-profile", "mozilla-intermediate"]),
            TlsProfile::MozillaIntermediate
        );
        assert_eq!(
            profile(&["--tls-profile", "kmip-1-basic"]),
            TlsProfile::Kmip1Basic
        );
        assert!(
            crate::Args::try_parse_from(base.iter().chain(&["--tls-profile", "kmip-0-none"]))
                .is_err()
        );
    }

    /// Each policy against the pinned Profiles text as recorded in the
    /// inventory: every SHALL version and suite is enabled, nothing a suite
    /// forbids is, and in a closed list every enabled suite and group is
    /// listed. A MAY list given by reference to unpinned NIST tables (1.1)
    /// counts as empty, so only mandatory suites may be enabled there.
    // REQ:333cc01abc3cabff spec 1.1-3.0: the channel security follows the Profiles suites (this check and the
    // negotiation tests above, for the policy selected with --tls-profile)
    #[test]
    fn every_policy_matches_the_profiles_inventory() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/specs/tls-profile-inventory.json");
        let inventory: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let strings = |v: &serde_json::Value| -> BTreeSet<String> {
            v.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        for p in POLICIES {
            let versions: BTreeSet<String> = p
                .versions
                .iter()
                .map(|v| version_name(*v).to_owned())
                .collect();
            let tls12: BTreeSet<String> =
                p.tls12_suites.iter().map(|s| s.iana.to_owned()).collect();
            let tls13: BTreeSet<String> = p.tls13_suites.iter().map(|s| s.to_string()).collect();
            let groups: BTreeSet<String> = p.groups.iter().map(|s| s.to_string()).collect();
            for (edition, name) in p.derived_from {
                let e = &inventory["editions"][edition]["suites"];
                let mut s = &e[name];
                assert!(s.is_object(), "{edition}/{name}");
                // HTTPS reuses the Basic protocols and cipher suites.
                if s["protocols"].is_string() {
                    s = &e["basic"];
                }
                let at = format!("{} vs {edition}/{name}", p.name);
                let proto = &s["protocols"];
                let required = &strings(&proto["shall"]) | &strings(&proto["server_shall"]);
                assert!(required.is_subset(&versions), "{at}: missing {required:?}");
                let mut forbidden = strings(&proto["shall_not"]);
                let only = strings(&proto["only"]);
                if !only.is_empty() {
                    assert_eq!(versions, only, "{at}");
                    forbidden
                        .extend(["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"].map(str::to_owned));
                    forbidden.retain(|v| !only.contains(v));
                }
                assert!(
                    versions.is_disjoint(&forbidden),
                    "{at}: forbidden {forbidden:?}"
                );
                let c = &s["ciphers"];
                let mut shall = &strings(&c["shall"]) | &strings(&c["server_shall"]);
                let mut shall13 = strings(&c["tls13_server_shall_all"]);
                if versions.contains("TLSv1.2") {
                    shall.extend(strings(&c["tls12_shall_if_tls12"]));
                }
                if versions.contains("TLSv1.3") {
                    shall13.extend(strings(&c["tls13_server_shall_all_if_tls13"]));
                }
                assert!(
                    shall.is_subset(&tls12),
                    "{at}: missing {:?}",
                    &shall - &tls12
                );
                assert!(
                    shall13.is_subset(&tls13),
                    "{at}: missing {:?}",
                    &shall13 - &tls13
                );
                if c["closed_list"] == true {
                    let mut allowed =
                        &(&shall | &strings(&c["may"])) | &strings(&c["tls12_may_if_tls12"]);
                    allowed.extend(strings(&c["tls12_shall_if_tls12"]));
                    let allowed13 = &strings(&c["tls13_server_shall_all"])
                        | &strings(&c["tls13_server_shall_all_if_tls13"]);
                    assert!(
                        tls12.is_subset(&allowed),
                        "{at}: unlisted {:?}",
                        &tls12 - &allowed
                    );
                    assert!(
                        tls13.is_subset(&allowed13),
                        "{at}: unlisted {:?}",
                        &tls13 - &allowed13
                    );
                }
                let g = &s["groups"];
                assert!(
                    strings(&g["server_shall_all"]).is_subset(&groups),
                    "{at}: groups"
                );
                if g["closed_list"] == true {
                    assert!(
                        groups.is_subset(&strings(&g["server_shall_all"])),
                        "{at}: unlisted groups"
                    );
                }
            }
        }
    }
}
