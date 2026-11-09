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

//! Incremental provider state; callers retain immutable snapshots until commit.
use super::*;
use openssl::{cipher::Cipher as ProviderCipher, cipher_ctx::CipherCtx, hash::Hasher};
use std::sync::Arc;

pub const MAX_AUTHENTICATED_PLAINTEXT: usize = 512 * 1024;
/// GCM decryption buffers authenticated plaintext, never releasing an unchecked prefix.
pub struct Aes {
    context: CipherCtx,
    encrypt: bool,
    gcm: bool,
    tag_len: usize,
    pending: Arc<Zeroizing<Vec<u8>>>,
}
impl Aes {
    pub fn new(
        encrypt: bool,
        key: &[u8],
        parameters: AesParameters,
        iv: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Self> {
        let cipher = match (key.len(), parameters.mode) {
            (16, CBC) => ProviderCipher::aes_128_cbc(),
            (24, CBC) => ProviderCipher::aes_192_cbc(),
            (32, CBC) => ProviderCipher::aes_256_cbc(),
            (16, ECB) => ProviderCipher::aes_128_ecb(),
            (24, ECB) => ProviderCipher::aes_192_ecb(),
            (32, ECB) => ProviderCipher::aes_256_ecb(),
            (16, CFB) => ProviderCipher::aes_128_cfb128(),
            (24, CFB) => ProviderCipher::aes_192_cfb128(),
            (32, CFB) => ProviderCipher::aes_256_cfb128(),
            (16, OFB) => ProviderCipher::aes_128_ofb(),
            (24, OFB) => ProviderCipher::aes_192_ofb(),
            (32, OFB) => ProviderCipher::aes_256_ofb(),
            (16, CTR) => ProviderCipher::aes_128_ctr(),
            (24, CTR) => ProviderCipher::aes_192_ctr(),
            (32, CTR) => ProviderCipher::aes_256_ctr(),
            (16, GCM) => ProviderCipher::aes_128_gcm(),
            (24, GCM) => ProviderCipher::aes_192_gcm(),
            (32, GCM) => ProviderCipher::aes_256_gcm(),
            _ => bail!("unsupported AES stream mechanism"),
        };
        if match parameters.mode {
            ECB => !iv.is_empty(),
            GCM => iv.is_empty() || iv.len() > 1024,
            _ => iv.len() != 16,
        } {
            bail!("invalid stream IV");
        }
        if matches!(parameters.mode, CBC | ECB)
            && ![padding::NONE, padding::PKCS5].contains(&parameters.padding)
            || !matches!(parameters.mode, CBC | ECB) && parameters.padding != padding::NONE
        {
            bail!("invalid stream padding");
        }
        if parameters.mode == GCM
            && (![4, 8, 12, 13, 14, 15, 16].contains(&parameters.tag_len)
                || !encrypt && tag.map(|t| t.len()) != Some(parameters.tag_len))
            || parameters.mode != GCM && (!aad.is_empty() || tag.is_some())
            || encrypt && tag.is_some()
        {
            bail!("invalid stream authentication parameters");
        }
        let mut context = CipherCtx::new()?;
        if encrypt {
            context.encrypt_init(Some(cipher), None, None)?;
        } else {
            context.decrypt_init(Some(cipher), None, None)?;
        }
        if parameters.mode == GCM {
            context.set_iv_length(iv.len())?;
        }
        let iv = if parameters.mode == ECB {
            None
        } else {
            Some(iv)
        };
        if encrypt {
            context.encrypt_init(None, Some(key), iv)?;
        } else {
            context.decrypt_init(None, Some(key), iv)?;
        }
        context.set_padding(
            matches!(parameters.mode, CBC | ECB) && parameters.padding == padding::PKCS5,
        );
        if parameters.mode == GCM {
            if let Some(tag) = tag {
                context.set_tag(tag)?;
            }
            context.cipher_update(aad, None)?;
        }
        Ok(Self {
            context,
            encrypt,
            gcm: parameters.mode == GCM,
            tag_len: parameters.tag_len,
            pending: Arc::new(Zeroizing::new(vec![])),
        })
    }
    /// Unauthenticated three-key TDEA-ECB/CBC sharing the block-mode snapshot logic.
    pub fn tdea(
        encrypt: bool,
        key: &[u8],
        parameters: super::tdea::Parameters,
        iv: &[u8],
    ) -> Result<Self> {
        super::tdea::check(key, parameters, iv)?;
        let cipher = match parameters.mode {
            CBC => ProviderCipher::des_ede3_cbc(),
            _ => ProviderCipher::des_ede3_ecb(),
        };
        let iv = if parameters.mode == ECB {
            None
        } else {
            Some(iv)
        };
        let mut context = CipherCtx::new()?;
        if encrypt {
            context.encrypt_init(Some(cipher), Some(key), iv)?;
        } else {
            context.decrypt_init(Some(cipher), Some(key), iv)?;
        }
        context.set_padding(parameters.padding == padding::PKCS5);
        Ok(Self {
            context,
            encrypt,
            gcm: false,
            tag_len: 0,
            pending: Arc::new(Zeroizing::new(vec![])),
        })
    }
    pub fn try_clone(&self) -> Result<Self> {
        let mut context = CipherCtx::new()?;
        context.copy(&self.context)?;
        Ok(Self {
            context,
            encrypt: self.encrypt,
            gcm: self.gcm,
            tag_len: self.tag_len,
            pending: self.pending.clone(),
        })
    }
    pub fn retained(&self) -> usize {
        self.pending.len()
    }
    pub fn holds_plaintext(&self) -> bool {
        self.gcm && !self.encrypt
    }
    pub fn update(&mut self, data: &[u8], last: bool) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        if self.holds_plaintext()
            && self.pending.len().saturating_add(data.len()) > MAX_AUTHENTICATED_PLAINTEXT
        {
            bail!("authenticated plaintext exceeds stream buffer limit");
        }
        let mut out = Zeroizing::new(vec![0; data.len() + 32]);
        let used = self.context.cipher_update(data, Some(&mut out))?;
        let tail = if last {
            self.context.cipher_final(&mut out[used..])?
        } else {
            0
        };
        out.truncate(used + tail);
        if self.holds_plaintext() {
            Arc::make_mut(&mut self.pending).extend_from_slice(&out);
            if last {
                out = Zeroizing::new(self.pending.to_vec());
                self.pending = Arc::new(Zeroizing::new(vec![]));
            } else {
                out.clear();
            }
        }
        let mut tag = vec![];
        if last && self.gcm && self.encrypt {
            tag.resize(self.tag_len, 0);
            self.context.tag(&mut tag)?;
        }
        Ok((out, tag))
    }
}
/// RFC 2104 HMAC composition using independently copyable provider digest contexts.
#[derive(Clone)]
pub struct Hmac {
    inner: Hasher,
    outer: Hasher,
}
impl Hmac {
    pub fn new(hash_id: u32, key: &[u8]) -> Result<Self> {
        let md = super::authentication::digest(hash_id)?;
        let block = md.block_size();
        let key = if key.len() > block {
            Zeroizing::new(hash(md, key)?.to_vec())
        } else {
            Zeroizing::new(key.to_vec())
        };
        let mut ipad = Zeroizing::new(vec![0x36; block]);
        let mut opad = Zeroizing::new(vec![0x5c; block]);
        for (i, b) in key.iter().enumerate() {
            ipad[i] ^= b;
            opad[i] ^= b;
        }
        let mut inner = Hasher::new(md)?;
        inner.update(&ipad)?;
        let mut outer = Hasher::new(md)?;
        outer.update(&opad)?;
        Ok(Self { inner, outer })
    }
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        Ok(self.inner.update(data)?)
    }
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let digest = self.inner.finish()?;
        self.outer.update(&digest)?;
        Ok(self.outer.finish()?.to_vec())
    }
}

/// Copyable MAC contexts keep transaction rollback independent of later updates.
pub enum Mac {
    Hmac(Hmac),
    Cmac(Cmac),
}
impl Mac {
    pub fn new(mechanism: super::authentication::Mechanism, key: &[u8]) -> Result<Self> {
        Ok(match mechanism {
            super::authentication::Mechanism::Hmac(hash) => Self::Hmac(Hmac::new(hash, key)?),
            super::authentication::Mechanism::Cmac => Self::Cmac(Cmac::new(key)?),
        })
    }
    pub fn try_clone(&self) -> Result<Self> {
        Ok(match self {
            Self::Hmac(h) => Self::Hmac(h.clone()),
            Self::Cmac(c) => Self::Cmac(c.try_clone()?),
        })
    }
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Self::Hmac(h) => h.update(data),
            Self::Cmac(c) => c.update(data),
        }
    }
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        match self {
            Self::Hmac(h) => h.finish(),
            Self::Cmac(c) => c.finish(),
        }
    }
}
/// NIST SP 800-38B/RFC 4493 CMAC over the provider's AES block primitive.
/// Only the final block is retained. Subkeys and chaining state are zeroized.
pub struct Cmac {
    context: CipherCtx,
    chain: Zeroizing<[u8; 16]>,
    pending: Zeroizing<Vec<u8>>,
    k1: Zeroizing<[u8; 16]>,
    k2: Zeroizing<[u8; 16]>,
}
impl Cmac {
    pub fn new(key: &[u8]) -> Result<Self> {
        let cipher = match key.len() {
            16 => ProviderCipher::aes_128_ecb(),
            24 => ProviderCipher::aes_192_ecb(),
            32 => ProviderCipher::aes_256_ecb(),
            _ => bail!("Invalid AES-CMAC key length"),
        };
        let mut context = CipherCtx::new()?;
        context.encrypt_init(Some(cipher), Some(key), None)?;
        context.set_padding(false);
        let l = Self::block(&mut context, &[0; 16])?;
        let k1 = Self::double(&l);
        let k2 = Self::double(&k1);
        Ok(Self {
            context,
            chain: Zeroizing::new([0; 16]),
            pending: Zeroizing::new(Vec::with_capacity(16)),
            k1,
            k2,
        })
    }
    fn block(context: &mut CipherCtx, input: &[u8]) -> Result<Zeroizing<[u8; 16]>> {
        let mut output = Zeroizing::new([0; 32]);
        if input.len() != 16 || context.cipher_update(input, Some(&mut *output))? != 16 {
            bail!("Invalid AES block result");
        }
        let mut result = Zeroizing::new([0; 16]);
        result.copy_from_slice(&output[..16]);
        Ok(result)
    }
    fn double(input: &[u8; 16]) -> Zeroizing<[u8; 16]> {
        let mut output = Zeroizing::new([0; 16]);
        for i in 0..16 {
            output[i] = input[i] << 1 | if i < 15 { input[i + 1] >> 7 } else { 0 };
        }
        output[15] ^= 0x87 & (0u8.wrapping_sub(input[0] >> 7));
        output
    }
    fn absorb(&mut self, input: &[u8]) -> Result<()> {
        let mut block = Zeroizing::new([0; 16]);
        for i in 0..16 {
            block[i] = input[i] ^ self.chain[i];
        }
        self.chain = Self::block(&mut self.context, &*block)?;
        Ok(())
    }
    pub fn try_clone(&self) -> Result<Self> {
        let mut context = CipherCtx::new()?;
        context.copy(&self.context)?;
        Ok(Self {
            context,
            chain: self.chain.clone(),
            pending: self.pending.clone(),
            k1: self.k1.clone(),
            k2: self.k2.clone(),
        })
    }
    pub fn update(&mut self, mut data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if !self.pending.is_empty() {
            let take = (16 - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
            if !data.is_empty() {
                let mut block = Zeroizing::new([0; 16]);
                block.copy_from_slice(&self.pending);
                self.absorb(&*block)?;
                self.pending.clear();
            }
        }
        while data.len() > 16 {
            self.absorb(&data[..16])?;
            data = &data[16..];
        }
        self.pending.extend_from_slice(data);
        Ok(())
    }
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut block = Zeroizing::new([0; 16]);
        block[..self.pending.len()].copy_from_slice(&self.pending);
        let subkey = if self.pending.len() == 16 {
            &self.k1
        } else {
            block[self.pending.len()] = 0x80;
            &self.k2
        };
        for i in 0..16 {
            block[i] ^= subkey[i];
        }
        self.absorb(&*block)?;
        Ok(self.chain.to_vec())
    }
}

/// Cipher-discriminated snapshots retain the existing AES implementation;
/// TDEA reuses its unauthenticated block-mode context.
pub enum Symmetric {
    Aes(Aes),
    ChaCha(super::chacha::Context),
}
impl Symmetric {
    pub fn new(
        encrypt: bool,
        key: &[u8],
        parameters: CipherParameters,
        iv: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Self> {
        Ok(match parameters {
            CipherParameters::Aes(p) => Self::Aes(Aes::new(encrypt, key, p, iv, aad, tag)?),
            CipherParameters::ChaCha(p) => {
                Self::ChaCha(super::chacha::Context::new(encrypt, key, p, iv, aad, tag)?)
            }
            CipherParameters::TripleDes(p) => {
                if !aad.is_empty() || tag.is_some() {
                    bail!("TDEA has no authenticated mode");
                }
                Self::Aes(Aes::tdea(encrypt, key, p, iv)?)
            }
        })
    }
    pub fn try_clone(&self) -> Result<Self> {
        Ok(match self {
            Self::Aes(c) => Self::Aes(c.try_clone()?),
            Self::ChaCha(c) => Self::ChaCha(c.try_clone()?),
        })
    }
    pub fn retained(&self) -> usize {
        match self {
            Self::Aes(c) => c.retained(),
            Self::ChaCha(c) => c.retained(),
        }
    }
    pub fn holds_plaintext(&self) -> bool {
        match self {
            Self::Aes(c) => c.holds_plaintext(),
            Self::ChaCha(c) => c.holds_plaintext(),
        }
    }
    pub fn update(&mut self, data: &[u8], last: bool) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        match self {
            Self::Aes(c) => c.update(data, last),
            Self::ChaCha(c) => c.update(data, last),
        }
    }
}
