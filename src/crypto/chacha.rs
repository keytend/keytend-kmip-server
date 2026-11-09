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

//! ChaCha20 provider contexts with explicit counter bounds and authenticated output release.
use anyhow::{Result, bail};
use openssl::{cipher::Cipher, cipher_ctx::CipherCtx};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub authenticated: bool,
    pub initial_counter: u64,
}

pub struct Context {
    context: CipherCtx,
    encrypt: bool,
    authenticated: bool,
    remaining: u128,
    pending: Arc<Zeroizing<Vec<u8>>>,
    max_plaintext: usize,
    finished: bool,
}
impl Context {
    /// Raw ChaCha20 accepts the original 64-bit or IETF 96-bit nonce.
    /// AEAD uses a 96-bit nonce and the provider's fixed counter construction.
    pub fn new(
        encrypt: bool,
        key: &[u8],
        parameters: Parameters,
        nonce: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Self> {
        if key.len() != 32 {
            bail!("ChaCha20 requires a 256-bit key");
        }
        let mut iv = Vec::new();
        let (cipher, remaining) = if parameters.authenticated {
            if nonce.len() != 12
                || parameters.initial_counter != 0
                || encrypt && tag.is_some()
                || !encrypt && tag.map(|t| t.len()) != Some(16)
            {
                bail!("Invalid ChaCha20-Poly1305 parameters");
            }
            iv.extend_from_slice(nonce);
            (Cipher::chacha20_poly1305(), ((1u128 << 32) - 1) * 64)
        } else {
            if !aad.is_empty() || tag.is_some() {
                bail!("Raw ChaCha20 has no authentication fields");
            }
            let bits = match nonce.len() {
                8 => {
                    iv.extend_from_slice(&parameters.initial_counter.to_le_bytes());
                    64
                }
                12 if parameters.initial_counter <= u32::MAX as u64 => {
                    iv.extend_from_slice(&(parameters.initial_counter as u32).to_le_bytes());
                    32
                }
                _ => bail!("Invalid ChaCha20 nonce or counter"),
            };
            iv.extend_from_slice(nonce);
            (
                Cipher::chacha20(),
                ((1u128 << bits) - parameters.initial_counter as u128) * 64,
            )
        };
        let mut context = CipherCtx::new()?;
        if encrypt {
            context.encrypt_init(Some(cipher), Some(key), Some(&iv))?;
        } else {
            context.decrypt_init(Some(cipher), Some(key), Some(&iv))?;
        }
        context.set_padding(false);
        if parameters.authenticated {
            if let Some(tag) = tag {
                context.set_tag(tag)?;
            }
            context.cipher_update(aad, None)?;
        }
        Ok(Self {
            context,
            encrypt,
            authenticated: parameters.authenticated,
            remaining,
            pending: Arc::new(Zeroizing::new(vec![])),
            max_plaintext: super::stream::MAX_AUTHENTICATED_PLAINTEXT,
            finished: false,
        })
    }
    pub fn try_clone(&self) -> Result<Self> {
        let mut context = CipherCtx::new()?;
        context.copy(&self.context)?;
        Ok(Self {
            context,
            encrypt: self.encrypt,
            authenticated: self.authenticated,
            remaining: self.remaining,
            pending: self.pending.clone(),
            max_plaintext: self.max_plaintext,
            finished: self.finished,
        })
    }
    pub fn retained(&self) -> usize {
        self.pending.len()
    }
    pub fn holds_plaintext(&self) -> bool {
        self.authenticated && !self.encrypt
    }
    pub fn update(&mut self, data: &[u8], last: bool) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        if self.finished {
            bail!("Cipher context already finalized");
        }
        if data.len() as u128 > self.remaining {
            bail!("ChaCha20 counter exhausted");
        }
        if self.holds_plaintext() && self.retained().saturating_add(data.len()) > self.max_plaintext
        {
            bail!("Authenticated plaintext buffer limit exceeded");
        }
        let result = self.apply(data, last);
        if last || result.is_err() {
            self.finished = true;
        }
        result
    }
    fn apply(&mut self, data: &[u8], last: bool) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let mut output = Zeroizing::new(vec![0; data.len() + 32]);
        let used = self.context.cipher_update(data, Some(&mut output))?;
        let tail = if last {
            self.context.cipher_final(&mut output[used..])?
        } else {
            0
        };
        self.remaining -= data.len() as u128;
        output.truncate(used + tail);
        if self.holds_plaintext() {
            Arc::make_mut(&mut self.pending).extend_from_slice(&output);
            if last {
                output = Zeroizing::new(self.pending.to_vec());
                self.pending = Arc::new(Zeroizing::new(vec![]));
            } else {
                output.clear();
            }
        }
        let mut tag = vec![];
        if last && self.authenticated && self.encrypt {
            tag.resize(16, 0);
            self.context.tag(&mut tag)?;
        }
        Ok((output, tag))
    }
}

pub fn crypt(
    encrypt: bool,
    key: &[u8],
    parameters: Parameters,
    nonce: &[u8],
    data: &[u8],
    aad: &[u8],
    tag: Option<&[u8]>,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let mut context = Context::new(encrypt, key, parameters, nonce, aad, tag)?;
    // A one-shot request has its own frame bound; the multipart retained-prefix
    // limit does not constrain its already bounded complete input.
    context.max_plaintext = data.len();
    context.update(data, true)
}
