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

//! DSA application-signature verification; signatures use canonical DER framing.
use anyhow::{Result, ensure};
use openssl::{
    dsa::DsaSig,
    hash::hash,
    md::Md,
    pkey::{Id, PKey},
    pkey_ctx::PkeyCtx,
};
pub fn verify(
    key: &[u8],
    algorithm: u32,
    data: &[u8],
    prehashed: bool,
    signature: &[u8],
) -> Result<bool> {
    let key = PKey::public_key_from_der(key)?;
    ensure!(key.id() == Id::DSA, "DSA public key required");
    let md = super::rsa::digest(algorithm)?;
    let digest = if prehashed {
        ensure!(data.len() == md.size(), "DSA digest length mismatch");
        data.to_vec()
    } else {
        hash(md, data)?.to_vec()
    };
    match DsaSig::from_der(signature) {
        Ok(sig) if sig.to_der()?.as_slice() == signature => (),
        _ => return Ok(false),
    }
    let mut ctx = PkeyCtx::new(&key)?;
    ctx.verify_init()?;
    ctx.set_signature_md(
        Md::from_nid(md.type_()).ok_or_else(|| anyhow::anyhow!("DSA digest unavailable"))?,
    )?;
    Ok(ctx.verify(&digest, signature).unwrap_or(false))
}
