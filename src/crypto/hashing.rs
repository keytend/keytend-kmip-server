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

//! Unkeyed SHA mechanisms for Hash, separate from signature and MAC policy.
use anyhow::{Result, anyhow, bail};
use openssl::hash::{MessageDigest, hash};

pub fn digest(algorithm: u32) -> Result<MessageDigest> {
    match algorithm {
        4..=8 | 14..=17 => super::authentication::digest(algorithm),
        // These have distinct initial values, not truncated SHA-512 output.
        12 => MessageDigest::from_name("SHA512-224")
            .ok_or_else(|| anyhow!("SHA-512/224 unavailable from provider")),
        13 => MessageDigest::from_name("SHA512-256")
            .ok_or_else(|| anyhow!("SHA-512/256 unavailable from provider")),
        _ => bail!("Unsupported unkeyed hash algorithm"),
    }
}

pub fn compute(algorithm: u32, data: &[u8]) -> Result<Vec<u8>> {
    Ok(hash(digest(algorithm)?, data)?.to_vec())
}
