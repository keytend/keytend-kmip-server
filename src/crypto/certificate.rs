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

//! X.509 metadata inspection. Parsing does not establish trust or validate signatures.
use anyhow::{Result, bail, ensure};
use openssl::{asn1::Asn1Object, nid::Nid, pkey::Id, x509::X509};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    /// Generic EC (26) does not infer ECDSA/ECDH use from a public point.
    pub algorithm: u32,
    pub bits: u32,
    pub signature: Option<u32>,
    /// Certificate Length is bytes, not public-key bits.
    pub length: u32,
}
pub fn inspect(der: &[u8]) -> Result<Metadata> {
    ensure!(
        !der.is_empty() && der.len() <= 65536,
        "Certificate size limit"
    );
    let cert = X509::from_der(der)?;
    ensure!(
        cert.to_der()? == der,
        "Trailing or reencoded certificate data"
    );
    let key = cert.public_key()?;
    let algorithm = match key.id() {
        Id::RSA | Id::RSA_PSS => 4,
        Id::DSA => 5,
        Id::DH | Id::DHX => 13,
        Id::EC => 26,
        _ => bail!("Unsupported certificate subject public-key algorithm"),
    };
    let signature = match cert.signature_algorithm().object().nid() {
        Nid::MD2WITHRSAENCRYPTION => Some(1),
        Nid::MD5WITHRSAENCRYPTION => Some(2),
        Nid::SHA1WITHRSAENCRYPTION => Some(3),
        Nid::SHA224WITHRSAENCRYPTION => Some(4),
        Nid::SHA256WITHRSAENCRYPTION => Some(5),
        Nid::SHA384WITHRSAENCRYPTION => Some(6),
        Nid::SHA512WITHRSAENCRYPTION => Some(7),
        Nid::RSASSAPSS => Some(8),
        Nid::DSAWITHSHA1 | Nid::DSAWITHSHA1_2 => Some(9),
        Nid::DSA_WITH_SHA224 => Some(10),
        Nid::DSA_WITH_SHA256 => Some(11),
        Nid::ECDSA_WITH_SHA1 => Some(12),
        Nid::ECDSA_WITH_SHA224 => Some(13),
        Nid::ECDSA_WITH_SHA256 => Some(14),
        Nid::ECDSA_WITH_SHA384 => Some(15),
        Nid::ECDSA_WITH_SHA512 => Some(16),
        other => [
            ("2.16.840.1.101.3.4.3.14", 17),
            ("2.16.840.1.101.3.4.3.15", 18),
            ("2.16.840.1.101.3.4.3.16", 19),
        ]
        .iter()
        .find_map(|(oid, value)| {
            let candidate = Asn1Object::from_str(oid).ok()?.nid();
            (candidate != Nid::UNDEF && candidate == other).then_some(*value)
        }),
    };
    Ok(Metadata {
        algorithm,
        bits: key.bits(),
        signature,
        length: der.len() as u32,
    })
}
