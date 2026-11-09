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

//! Bounded KDF constructions using OpenSSL hash, HMAC, CMAC and PBKDF providers.
use anyhow::{Result, bail, ensure};
use openssl::{
    hash::MessageDigest,
    md::{Md, MdRef},
    pkey::PKey,
    sign::Signer,
    symm::Cipher,
};
use zeroize::Zeroizing;

pub const MAX_OUTPUT: usize = 65536;
pub const MAX_WORK: usize = 2_000_000;
fn size(len: usize) -> Result<()> {
    ensure!(
        (1..=MAX_OUTPUT).contains(&len),
        "KDF output size out of range"
    );
    Ok(())
}
pub fn digest(hash: u32) -> Result<MessageDigest> {
    super::authentication::digest(hash)
}
fn md(hash: u32) -> Result<&'static MdRef> {
    Ok(match hash {
        3 => Md::md5(),
        4 => Md::sha1(),
        5 => Md::sha224(),
        6 => Md::sha256(),
        7 => Md::sha384(),
        8 => Md::sha512(),
        14 => Md::sha3_224(),
        15 => Md::sha3_256(),
        16 => Md::sha3_384(),
        17 => Md::sha3_512(),
        _ => bail!("Unsupported KDF hash"),
    })
}
#[derive(Clone, Copy)]
pub enum Prf {
    Hmac(u32),
    Cmac,
}
impl Prf {
    pub fn output_len(self) -> Result<usize> {
        Ok(match self {
            Self::Hmac(hash) => digest(hash)?.size(),
            Self::Cmac => 16,
        })
    }
    pub fn compute(self, key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            key.len() <= MAX_OUTPUT && data.len() <= MAX_OUTPUT + 128,
            "KDF input too large"
        );
        let key = match self {
            Self::Hmac(_) => PKey::hmac(key)?,
            Self::Cmac => {
                let cipher = match key.len() {
                    16 => Cipher::aes_128_cbc(),
                    24 => Cipher::aes_192_cbc(),
                    32 => Cipher::aes_256_cbc(),
                    _ => bail!("Invalid CMAC key length"),
                };
                PKey::cmac(&cipher, key)?
            }
        };
        let mut signer = match self {
            Self::Hmac(hash) => Signer::new(digest(hash)?, &key)?,
            Self::Cmac => Signer::new_without_digest(&key)?,
        };
        signer.update(data)?;
        Ok(Zeroizing::new(signer.sign_to_vec()?))
    }
}
pub fn hash(hash: u32, data: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    size(len)?;
    ensure!(data.len() <= MAX_OUTPUT, "KDF input too large");
    let mut out = Zeroizing::new(openssl::hash::hash(digest(hash)?, data)?.to_vec());
    ensure!(len <= out.len(), "Requested output exceeds hash output");
    out.truncate(len);
    Ok(out)
}
pub fn pbkdf2(
    hash: u32,
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    size(len)?;
    ensure!(
        password.len() <= MAX_OUTPUT && salt.len() <= MAX_OUTPUT,
        "PBKDF2 input too large"
    );
    let md = digest(hash)?;
    let blocks = len.div_ceil(md.size());
    ensure!(
        iterations > 0 && iterations <= MAX_WORK / blocks,
        "PBKDF2 work limit exceeded"
    );
    let mut out = Zeroizing::new(vec![0; len]);
    openssl::pkcs5::pbkdf2_hmac(password, salt, iterations, md, &mut out)?;
    Ok(out)
}
pub fn hkdf(
    hash: u32,
    key: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    size(len)?;
    ensure!(
        len <= 255 * digest(hash)?.size(),
        "HKDF output exceeds 255 digest blocks"
    );
    ensure!(
        [key.len(), salt.len(), info.len()]
            .into_iter()
            .all(|n| n <= MAX_OUTPUT),
        "HKDF input too large"
    );
    let mut out = Zeroizing::new(vec![0; len]);
    openssl::kdf::hkdf(
        md(hash)?,
        key,
        Some(salt),
        Some(info),
        openssl::kdf::HkdfMode::ExtractAndExpand,
        None,
        &mut out,
    )?;
    Ok(out)
}
pub fn aws_v4(
    secret: &[u8],
    date: &[u8],
    region: &[u8],
    service: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    size(len)?;
    ensure!(
        len <= 32 && secret.len() <= MAX_OUTPUT - 4,
        "Invalid AWS KDF output/input length"
    );
    let mut key = Zeroizing::new(b"AWS4".to_vec());
    key.extend_from_slice(secret);
    for data in [date, region, service, b"aws4_request"] {
        key = Prf::Hmac(6).compute(&key, data)?;
    }
    key.truncate(len);
    Ok(key)
}
#[derive(Clone, Copy)]
pub enum Mode {
    Counter,
    Feedback,
    DoublePipeline,
}
#[derive(Clone, Copy)]
pub enum CounterLocation {
    BeforeIteration,
    AfterIteration,
    AfterFixed,
}
pub struct KbkdfParameters<'a> {
    pub mode: Mode,
    pub prf: Prf,
    pub fixed: &'a [u8],
    pub iv: &'a [u8],
    /// Width and placement are exposed for published CAVP vector verification.
    /// The KMIP mapping uses a 32-bit counter, after the iteration value.
    pub counter_bytes: usize,
    pub counter_location: CounterLocation,
}
pub fn sp800108(key: &[u8], p: KbkdfParameters<'_>, len: usize) -> Result<Zeroizing<Vec<u8>>> {
    size(len)?;
    let block_len = p.prf.output_len()?;
    let blocks = len.div_ceil(block_len);
    ensure!(
        (1..=4).contains(&p.counter_bytes),
        "Invalid KDF counter width"
    );
    ensure!(
        (blocks as u64) < (1u64 << (8 * p.counter_bytes)),
        "KDF counter overflow"
    );
    ensure!(
        p.fixed.len() <= MAX_OUTPUT + 4 && p.iv.len() <= MAX_OUTPUT,
        "KDF input too large"
    );
    ensure!(
        blocks
            .saturating_mul(p.fixed.len().div_ceil(64) + 4)
            .saturating_mul(2)
            <= MAX_WORK,
        "KDF work limit exceeded"
    );
    ensure!(
        matches!(p.mode, Mode::Feedback) || p.iv.is_empty(),
        "Only Feedback uses an IV"
    );
    ensure!(
        p.iv.is_empty() || p.iv.len() == block_len,
        "Invalid Feedback IV length"
    );
    let mut iteration = Zeroizing::new(match p.mode {
        Mode::Counter => vec![],
        Mode::Feedback => p.iv.to_vec(),
        Mode::DoublePipeline => p.fixed.to_vec(),
    });
    let mut out = Zeroizing::new(Vec::with_capacity(blocks * block_len));
    for index in 1..=blocks {
        if matches!(p.mode, Mode::DoublePipeline) {
            iteration = p.prf.compute(key, &iteration)?;
        }
        let bytes = (index as u32).to_be_bytes();
        let counter = &bytes[4 - p.counter_bytes..];
        let mut input = Zeroizing::new(Vec::with_capacity(p.fixed.len() + iteration.len() + 4));
        let parts: [&[u8]; 3] = match p.counter_location {
            CounterLocation::BeforeIteration => [counter, &iteration, p.fixed],
            CounterLocation::AfterIteration => [&iteration, counter, p.fixed],
            CounterLocation::AfterFixed => [&iteration, p.fixed, counter],
        };
        for part in parts {
            input.extend_from_slice(part);
        }
        let block = p.prf.compute(key, &input)?;
        out.extend_from_slice(&block);
        if matches!(p.mode, Mode::Feedback) {
            iteration = block;
        }
    }
    out.truncate(len);
    Ok(out)
}
