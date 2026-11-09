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

//! AES key wrap through the system provider, with mandatory integrity verification.
use anyhow::{Result, bail};
use openssl::{
    cipher::Cipher,
    cipher_ctx::{CipherCtx, CipherCtxFlags},
};
use zeroize::Zeroizing;

pub fn aes(key: &[u8], data: &[u8], padded: bool, encrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() > crate::ttlv::MAX_FRAME
        || data.is_empty()
        || encrypt && !padded && (data.len() < 16 || !data.len().is_multiple_of(8))
        || !encrypt && (data.len() < if padded { 16 } else { 24 } || !data.len().is_multiple_of(8))
    {
        bail!("invalid AES key wrap length");
    }
    let cipher = match (key.len(), padded) {
        (16, false) => Cipher::aes_128_wrap(),
        (24, false) => Cipher::aes_192_wrap(),
        (32, false) => Cipher::aes_256_wrap(),
        (16, true) => Cipher::aes_128_wrap_pad(),
        (24, true) => Cipher::aes_192_wrap_pad(),
        (32, true) => Cipher::aes_256_wrap_pad(),
        _ => bail!("invalid AES wrapping key length"),
    };
    let mut ctx = CipherCtx::new()?;
    ctx.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
    if encrypt {
        ctx.encrypt_init(Some(cipher), Some(key), None)?;
    } else {
        ctx.decrypt_init(Some(cipher), Some(key), None)?;
    }
    let mut output = Zeroizing::new(vec![0; data.len() + 32]);
    let used = ctx.cipher_update(data, Some(&mut output))?;
    let tail = ctx.cipher_final(&mut output[used..])?;
    output.truncate(used + tail);
    Ok(output)
}
