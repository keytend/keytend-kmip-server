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

//! Explicit RSA mechanisms; provider defaults never select KMIP parameters.
use anyhow::{Result, bail};
use openssl::{
    encrypt::{Decrypter, Encrypter},
    hash::{MessageDigest, hash},
    md::{Md, MdRef},
    pkey::{PKey, Public},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::RsaPssSaltlen,
};
use zeroize::Zeroizing;

pub fn digest(algorithm: u32) -> Result<MessageDigest> {
    Ok(match algorithm {
        4 => MessageDigest::sha1(),
        5 => MessageDigest::sha224(),
        6 => MessageDigest::sha256(),
        7 => MessageDigest::sha384(),
        8 => MessageDigest::sha512(),
        _ => bail!("unsupported RSA digest"),
    })
}
fn md(algorithm: u32) -> Result<&'static MdRef> {
    Md::from_nid(digest(algorithm)?.type_())
        .ok_or_else(|| anyhow::anyhow!("RSA digest unavailable"))
}
fn public_key(data: &[u8]) -> Result<PKey<Public>> {
    PKey::public_key_from_der(data)
        .or_else(|_| Rsa::public_key_from_der_pkcs1(data).and_then(PKey::from_rsa))
        .map_err(Into::into)
}
/// RSA key generation through EVP, in the loaded provider (the low-level
/// RSA_generate_key_ex would bypass it). The public exponent is 65537.
pub fn generate(bits: u32) -> Result<PKey<openssl::pkey::Private>> {
    let mut ctx = PkeyCtx::new_id(openssl::pkey::Id::RSA)?;
    ctx.keygen_init()?;
    ctx.set_rsa_keygen_bits(bits)?;
    Ok(ctx.keygen()?)
}
pub fn export(key: &[u8], private: bool, format: u32) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = if private {
        let key = PKey::private_key_from_der(key)?;
        match format {
            3 => key.rsa()?.private_key_to_der()?,
            4 => key.private_key_to_pkcs8()?,
            _ => bail!("unsupported private key format"),
        }
    } else {
        let key = public_key(key)?;
        match format {
            3 => key.rsa()?.public_key_to_der_pkcs1()?,
            5 => key.public_key_to_der()?,
            _ => bail!("unsupported public key format"),
        }
    };
    Ok(Zeroizing::new(bytes))
}

#[derive(Clone, Copy)]
pub struct OaepParameters<'a> {
    pub hash: u32,
    pub mgf_hash: u32,
    pub label: &'a [u8],
}

pub fn oaep_encrypt(key: &[u8], parameters: OaepParameters<'_>, data: &[u8]) -> Result<Vec<u8>> {
    let key = public_key(key)?;
    let mut ctx = Encrypter::new(&key)?;
    ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
    ctx.set_rsa_oaep_md(digest(parameters.hash)?)?;
    ctx.set_rsa_mgf1_md(digest(parameters.mgf_hash)?)?;
    if !parameters.label.is_empty() {
        ctx.set_rsa_oaep_label(parameters.label)?;
    }
    let mut out = vec![0; ctx.encrypt_len(data)?];
    let used = ctx.encrypt(data, &mut out)?;
    out.truncate(used);
    Ok(out)
}

pub fn oaep_decrypt(
    key: &[u8],
    parameters: OaepParameters<'_>,
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key = PKey::private_key_from_der(key)?;
    let mut ctx = Decrypter::new(&key)?;
    ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
    ctx.set_rsa_oaep_md(digest(parameters.hash)?)?;
    ctx.set_rsa_mgf1_md(digest(parameters.mgf_hash)?)?;
    if !parameters.label.is_empty() {
        ctx.set_rsa_oaep_label(parameters.label)?;
    }
    let mut out = Zeroizing::new(vec![0; ctx.decrypt_len(data)?]);
    let used = ctx.decrypt(data, &mut out)?;
    out.truncate(used);
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureParameters {
    pub hash: u32,
    pub pss: bool,
    pub mgf_hash: u32,
    pub salt_len: i32,
}
fn input_digest(
    parameters: SignatureParameters,
    data: &[u8],
    prehashed: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let md = digest(parameters.hash)?;
    if prehashed {
        if data.len() != md.size() {
            bail!("digested input length does not match hashing algorithm");
        }
        Ok(Zeroizing::new(data.to_vec()))
    } else {
        Ok(Zeroizing::new(hash(md, data)?.to_vec()))
    }
}
pub fn sign(
    key: &[u8],
    parameters: SignatureParameters,
    data: &[u8],
    prehashed: bool,
) -> Result<Vec<u8>> {
    let key = PKey::private_key_from_der(key)?;
    let mut ctx = PkeyCtx::new(&key)?;
    ctx.sign_init()?;
    ctx.set_rsa_padding(if parameters.pss {
        Padding::PKCS1_PSS
    } else {
        Padding::PKCS1
    })?;
    ctx.set_signature_md(md(parameters.hash)?)?;
    if parameters.pss {
        ctx.set_rsa_mgf1_md(md(parameters.mgf_hash)?)?;
        ctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(parameters.salt_len))?;
    }
    let digest = input_digest(parameters, data, prehashed)?;
    let mut out = vec![];
    ctx.sign_to_vec(&digest, &mut out)?;
    Ok(out)
}
pub fn verify(
    key: &[u8],
    parameters: SignatureParameters,
    data: &[u8],
    prehashed: bool,
    signature: &[u8],
) -> Result<bool> {
    let key = public_key(key)?;
    let mut ctx = PkeyCtx::new(&key)?;
    ctx.verify_init()?;
    ctx.set_rsa_padding(if parameters.pss {
        Padding::PKCS1_PSS
    } else {
        Padding::PKCS1
    })?;
    ctx.set_signature_md(md(parameters.hash)?)?;
    if parameters.pss {
        ctx.set_rsa_mgf1_md(md(parameters.mgf_hash)?)?;
        ctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(parameters.salt_len))?;
    }
    let digest = input_digest(parameters, data, prehashed)?;
    // Providers differ between zero and a negative return for a malformed or
    // mismatched RSA signature. Setup errors above remain operation failures;
    // an unsuccessful verification itself is a KMIP Invalid validity result.
    Ok(ctx.verify(&digest, signature).unwrap_or(false))
}
