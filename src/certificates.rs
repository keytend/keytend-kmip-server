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

use anyhow::{Result, bail};
use openssl::{
    stack::Stack,
    x509::{
        X509, X509StoreContext,
        store::X509StoreBuilder,
        verify::{X509VerifyFlags, X509VerifyParam},
    },
};

pub const MAX_CHAIN: usize = 32;
pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_CERT_BYTES: usize = 64 * 1024;

/// Explicit application trust, separate from transport client-authentication trust.
/// An empty policy cannot report an untrusted supplied root as Valid.
#[derive(Default)]
pub struct CertificateValidation {
    anchors: Vec<X509>,
}
impl CertificateValidation {
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        if pem.is_empty() || pem.len() > MAX_BYTES {
            bail!("validation trust bundle size invalid");
        }
        let mut anchors = vec![];
        let mut remaining = std::str::from_utf8(pem)?.trim();
        const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
        const END: &str = "-----END CERTIFICATE-----";
        while !remaining.is_empty() {
            if anchors.len() >= MAX_CHAIN || !remaining.starts_with(BEGIN) {
                bail!("invalid validation trust bundle");
            }
            let end = remaining
                .find(END)
                .ok_or_else(|| anyhow::anyhow!("incomplete validation trust anchor"))?
                + END.len();
            anchors.push(X509::from_pem(&remaining.as_bytes()[..end])?);
            remaining = remaining[end..].trim();
        }
        if anchors.is_empty() {
            bail!("validation trust anchor count invalid");
        }
        let mut seen = std::collections::HashSet::new();
        for anchor in &anchors {
            let der = anchor.to_der()?;
            let key = anchor.public_key()?;
            if der.len() > MAX_CERT_BYTES
                || key.bits() > 8192
                || key.rsa().is_ok_and(|rsa| rsa.e().num_bits() > 32)
            {
                bail!("validation trust anchor work limit exceeded");
            }
            if !seen.insert(der) {
                bail!("duplicate validation trust anchor");
            }
        }
        Ok(Self { anchors })
    }
    /// Verify exactly one supplied chain. Order is irrelevant; every supplied
    /// distinct certificate must occur in the verified path. Never load OS roots,
    /// fetch AIA/OCSP, or trust a root merely because it occurs in the request.
    pub fn validate(&self, certificates: &[X509], at: i64) -> Result<u32> {
        if certificates.is_empty() || certificates.len() > MAX_CHAIN {
            bail!("certificate chain size invalid");
        }
        let supplied = certificates
            .iter()
            .map(|c| c.to_der())
            .collect::<Result<Vec<_>, _>>()?;
        if supplied.iter().any(|c| c.len() > MAX_CERT_BYTES)
            || supplied.iter().map(Vec::len).sum::<usize>() > MAX_BYTES
        {
            bail!("certificate chain size invalid");
        }
        if self.anchors.is_empty() {
            return Ok(3);
        }
        for cert in certificates.iter().chain(&self.anchors) {
            let key = match cert.public_key() {
                Ok(key) => key,
                Err(_) => return Ok(3),
            };
            if key.bits() > 8192 || key.rsa().is_ok_and(|rsa| rsa.e().num_bits() > 32) {
                return Ok(2);
            }
        }
        let mut store = X509StoreBuilder::new()?;
        for anchor in &self.anchors {
            store.add_cert(anchor.clone())?;
        }
        let mut parameters = X509VerifyParam::new()?;
        parameters.set_time(native_time(at)?);
        parameters.set_depth((MAX_CHAIN - 1) as i32);
        parameters.set_auth_level(2);
        parameters.set_flags(
            X509VerifyFlags::X509_STRICT
                | X509VerifyFlags::CHECK_SS_SIGNATURE
                | X509VerifyFlags::TRUSTED_FIRST,
        )?;
        store.set_param(&parameters)?;
        let store = store.build();
        // Trying bounded candidates also handles self-issued rollover chains;
        // subject-name heuristics alone cannot identify their target reliably.
        let mut candidates = vec![];
        for (i, candidate) in certificates.iter().enumerate() {
            let mut issuer = false;
            for (j, other) in certificates.iter().enumerate() {
                if i != j
                    && candidate
                        .subject_name()
                        .try_cmp(other.issuer_name())?
                        .is_eq()
                {
                    issuer = true;
                    break;
                }
            }
            if !issuer {
                candidates.push(i);
            }
        }
        if candidates.is_empty() {
            candidates.extend(0..certificates.len());
        }
        for target in candidates {
            let certificate = &certificates[target];
            let mut untrusted = Stack::new()?;
            for (i, other) in certificates.iter().enumerate() {
                if i != target {
                    untrusted.push(other.clone())?;
                }
            }
            let mut context = X509StoreContext::new()?;
            let valid = context.init(&store, certificate, &untrusted, |ctx| {
                if !ctx.verify_cert()? {
                    return Ok(false);
                }
                let path = ctx
                    .chain()
                    .map(|chain| {
                        chain
                            .iter()
                            .map(|c| c.to_der())
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
                    .unwrap_or_default();
                Ok(supplied.iter().all(|cert| path.contains(cert)))
            })?;
            if valid {
                return Ok(1);
            }
        }
        Ok(2)
    }
}
fn native_time<T: TryFrom<i64>>(at: i64) -> Result<T> {
    at.try_into()
        .map_err(|_| anyhow::anyhow!("validation time is outside the platform range"))
}
