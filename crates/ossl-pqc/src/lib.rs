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

//! ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) through the
//! OpenSSL 3.5 providers.
//!
//! The safe `openssl` crate (0.10.81) names ML-KEM and ML-DSA keys but not
//! SLH-DSA, and has no key generation by algorithm name, no KEM
//! encapsulation and no message signing with a context string. The server
//! crate forbids `unsafe`, so this crate holds those calls, each behind a
//! safe function that takes one of the eighteen [`Algorithm`] parameter
//! sets (never a caller-supplied algorithm name) and refuses a key that is
//! not of that parameter set. Every call uses the process default library
//! context and property query, so FIPS mode (the "fips=yes" default
//! property) refuses these algorithms in the provider as well.
//!
//! What it does not offer, deliberately: the "test-entropy" signing
//! parameter (client-chosen signing randomness) and the internal
//! ("message-encoding" 0) interfaces of FIPS 204/205, which those
//! standards reserve for testing; and the pre-hash variants HashML-DSA and
//! HashSLH-DSA, which OpenSSL 3.5 does not implement.
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::error::ErrorStack;
use openssl::pkey::{HasPrivate, HasPublic, PKey, PKeyRef, Private, Public};
use openssl_sys::{EVP_PKEY, EVP_PKEY_CTX, OSSL_LIB_CTX, OSSL_PARAM};
use std::ffi::{CStr, c_char, c_int, c_void};
use std::ptr::{null, null_mut};
use zeroize::Zeroizing;

/// The algorithm family of a parameter set.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    /// FIPS 203 key-encapsulation mechanism.
    MlKem,
    /// FIPS 204 lattice signatures.
    MlDsa,
    /// FIPS 205 stateless hash-based signatures.
    SlhDsa,
}

/// One FIPS 203/204/205 parameter set, by its OpenSSL algorithm name.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Algorithm {
    name: &'static CStr,
    family: Family,
    category: u8,
}

const fn set(name: &'static CStr, family: Family, category: u8) -> Algorithm {
    Algorithm {
        name,
        family,
        category,
    }
}

impl Algorithm {
    pub const ML_KEM_512: Self = set(c"ML-KEM-512", Family::MlKem, 1);
    pub const ML_KEM_768: Self = set(c"ML-KEM-768", Family::MlKem, 3);
    pub const ML_KEM_1024: Self = set(c"ML-KEM-1024", Family::MlKem, 5);
    pub const ML_DSA_44: Self = set(c"ML-DSA-44", Family::MlDsa, 2);
    pub const ML_DSA_65: Self = set(c"ML-DSA-65", Family::MlDsa, 3);
    pub const ML_DSA_87: Self = set(c"ML-DSA-87", Family::MlDsa, 5);
    pub const SLH_DSA_SHA2_128S: Self = set(c"SLH-DSA-SHA2-128s", Family::SlhDsa, 1);
    pub const SLH_DSA_SHA2_128F: Self = set(c"SLH-DSA-SHA2-128f", Family::SlhDsa, 1);
    pub const SLH_DSA_SHA2_192S: Self = set(c"SLH-DSA-SHA2-192s", Family::SlhDsa, 3);
    pub const SLH_DSA_SHA2_192F: Self = set(c"SLH-DSA-SHA2-192f", Family::SlhDsa, 3);
    pub const SLH_DSA_SHA2_256S: Self = set(c"SLH-DSA-SHA2-256s", Family::SlhDsa, 5);
    pub const SLH_DSA_SHA2_256F: Self = set(c"SLH-DSA-SHA2-256f", Family::SlhDsa, 5);
    pub const SLH_DSA_SHAKE_128S: Self = set(c"SLH-DSA-SHAKE-128s", Family::SlhDsa, 1);
    pub const SLH_DSA_SHAKE_128F: Self = set(c"SLH-DSA-SHAKE-128f", Family::SlhDsa, 1);
    pub const SLH_DSA_SHAKE_192S: Self = set(c"SLH-DSA-SHAKE-192s", Family::SlhDsa, 3);
    pub const SLH_DSA_SHAKE_192F: Self = set(c"SLH-DSA-SHAKE-192f", Family::SlhDsa, 3);
    pub const SLH_DSA_SHAKE_256S: Self = set(c"SLH-DSA-SHAKE-256s", Family::SlhDsa, 5);
    pub const SLH_DSA_SHAKE_256F: Self = set(c"SLH-DSA-SHAKE-256f", Family::SlhDsa, 5);

    /// Every parameter set, ML-KEM, then ML-DSA, then SLH-DSA.
    pub const ALL: [Self; 18] = [
        Self::ML_KEM_512,
        Self::ML_KEM_768,
        Self::ML_KEM_1024,
        Self::ML_DSA_44,
        Self::ML_DSA_65,
        Self::ML_DSA_87,
        Self::SLH_DSA_SHA2_128S,
        Self::SLH_DSA_SHA2_128F,
        Self::SLH_DSA_SHA2_192S,
        Self::SLH_DSA_SHA2_192F,
        Self::SLH_DSA_SHA2_256S,
        Self::SLH_DSA_SHA2_256F,
        Self::SLH_DSA_SHAKE_128S,
        Self::SLH_DSA_SHAKE_128F,
        Self::SLH_DSA_SHAKE_192S,
        Self::SLH_DSA_SHAKE_192F,
        Self::SLH_DSA_SHAKE_256S,
        Self::SLH_DSA_SHAKE_256F,
    ];

    /// The OpenSSL (and FIPS) name, such as "ML-DSA-65".
    pub fn name(&self) -> &'static str {
        self.name.to_str().expect("ASCII algorithm name")
    }
    pub fn family(&self) -> Family {
        self.family
    }
    /// The NIST security category (FIPS 203 Table 2, FIPS 204 Table 1,
    /// FIPS 205 Table 2).
    pub fn security_category(&self) -> u8 {
        self.category
    }
    /// The length of the key-generation seed this server accepts: FIPS 203
    /// d || z (64 bytes), FIPS 204 xi (32 bytes). SLH-DSA has none here.
    pub fn seed_len(&self) -> Option<usize> {
        match self.family {
            Family::MlKem => Some(64),
            Family::MlDsa => Some(32),
            Family::SlhDsa => None,
        }
    }
}

/// Options of a pure (external-interface) ML-DSA or SLH-DSA signature.
#[derive(Copy, Clone, Debug, Default)]
pub struct SignatureOptions<'a> {
    /// The FIPS 204/205 context string ctx (at most 255 bytes).
    pub context: &'a [u8],
    /// Deterministic rather than hedged signing (FIPS 204 section 3.4,
    /// FIPS 205 section 9.2). Signing only.
    pub deterministic: bool,
    /// ML-DSA only: the message is the 64-byte mu of FIPS 204 Algorithm 7
    /// line 6, computed by the caller ("external mu").
    pub external_mu: bool,
}

// Opaque OpenSSL signature-algorithm handle.
#[repr(C)]
struct EvpSignature {
    _private: [u8; 0],
}

// Declared here, with the OpenSSL 3.5 signatures (<openssl/evp.h>,
// <openssl/params.h>), because openssl-sys gates several of them on build
// configuration flags this crate cannot see. libcrypto is linked through
// openssl-sys.
unsafe extern "C" {
    fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        propquery: *const c_char,
    ) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_new_from_pkey(
        libctx: *mut OSSL_LIB_CTX,
        pkey: *mut EVP_PKEY,
        propquery: *const c_char,
    ) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_keygen_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_generate(ctx: *mut EVP_PKEY_CTX, pkey: *mut *mut EVP_PKEY) -> c_int;
    fn EVP_PKEY_fromdata_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_fromdata(
        ctx: *mut EVP_PKEY_CTX,
        pkey: *mut *mut EVP_PKEY,
        selection: c_int,
        params: *mut OSSL_PARAM,
    ) -> c_int;
    fn EVP_PKEY_new_raw_private_key_ex(
        libctx: *mut OSSL_LIB_CTX,
        keytype: *const c_char,
        propq: *const c_char,
        key: *const u8,
        keylen: usize,
    ) -> *mut EVP_PKEY;
    fn EVP_PKEY_new_raw_public_key_ex(
        libctx: *mut OSSL_LIB_CTX,
        keytype: *const c_char,
        propq: *const c_char,
        key: *const u8,
        keylen: usize,
    ) -> *mut EVP_PKEY;
    fn EVP_PKEY_is_a(pkey: *const EVP_PKEY, name: *const c_char) -> c_int;
    fn EVP_PKEY_get_octet_string_param(
        pkey: *const EVP_PKEY,
        key_name: *const c_char,
        buf: *mut u8,
        max_buf_sz: usize,
        out_len: *mut usize,
    ) -> c_int;
    fn EVP_SIGNATURE_fetch(
        ctx: *mut OSSL_LIB_CTX,
        algorithm: *const c_char,
        properties: *const c_char,
    ) -> *mut EvpSignature;
    fn EVP_SIGNATURE_free(signature: *mut EvpSignature);
    fn EVP_PKEY_sign_message_init(
        ctx: *mut EVP_PKEY_CTX,
        algo: *mut EvpSignature,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_PKEY_verify_message_init(
        ctx: *mut EVP_PKEY_CTX,
        algo: *mut EvpSignature,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_PKEY_sign(
        ctx: *mut EVP_PKEY_CTX,
        sig: *mut u8,
        siglen: *mut usize,
        tbs: *const u8,
        tbslen: usize,
    ) -> c_int;
    fn EVP_PKEY_verify(
        ctx: *mut EVP_PKEY_CTX,
        sig: *const u8,
        siglen: usize,
        tbs: *const u8,
        tbslen: usize,
    ) -> c_int;
    fn EVP_PKEY_encapsulate_init(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int;
    fn EVP_PKEY_encapsulate(
        ctx: *mut EVP_PKEY_CTX,
        wrappedkey: *mut u8,
        wrappedkeylen: *mut usize,
        genkey: *mut u8,
        genkeylen: *mut usize,
    ) -> c_int;
    fn EVP_PKEY_decapsulate_init(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int;
    fn EVP_PKEY_decapsulate(
        ctx: *mut EVP_PKEY_CTX,
        unwrapped: *mut u8,
        unwrappedlen: *mut usize,
        wrapped: *const u8,
        wrappedlen: usize,
    ) -> c_int;
    fn OSSL_PARAM_construct_octet_string(
        key: *const c_char,
        buf: *mut c_void,
        bsize: usize,
    ) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_end() -> OSSL_PARAM;
}

/// EVP_PKEY_KEYPAIR (<openssl/evp.h>): public key, private key and all
/// domain parameters.
const EVP_PKEY_KEYPAIR: c_int = 0x87;

fn cvt(r: c_int) -> Result<(), ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(())
    }
}
fn cvt_p<T>(p: *mut T) -> Result<*mut T, ErrorStack> {
    if p.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(p)
    }
}

/// An owned EVP_PKEY_CTX, freed on drop.
struct Ctx(*mut EVP_PKEY_CTX);
impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: self.0 is a non-null context this value owns exclusively.
        unsafe { EVP_PKEY_CTX_free(self.0) }
    }
}
impl Ctx {
    fn from_name(alg: Algorithm) -> Result<Self, ErrorStack> {
        openssl::init();
        // SAFETY: the name is a 'static NUL-terminated string; null library
        // context and property query select the process defaults.
        let p = unsafe { EVP_PKEY_CTX_new_from_name(null_mut(), alg.name.as_ptr(), null()) };
        Ok(Ctx(cvt_p(p)?))
    }
    fn from_pkey<T>(key: &PKeyRef<T>) -> Result<Self, ErrorStack> {
        // SAFETY: `key` is a live EVP_PKEY; the new context takes its own
        // reference to it, so the context may outlive the borrow.
        let p = unsafe { EVP_PKEY_CTX_new_from_pkey(null_mut(), key.as_ptr(), null()) };
        Ok(Ctx(cvt_p(p)?))
    }
}

/// An owned EVP_SIGNATURE, freed on drop.
struct Signature(*mut EvpSignature);
impl Drop for Signature {
    fn drop(&mut self) {
        // SAFETY: self.0 is a non-null fetched algorithm this value owns.
        unsafe { EVP_SIGNATURE_free(self.0) }
    }
}

/// A caller error the provider never saw. ErrorStack has no public
/// constructor with text, so this drains (and returns) the thread's queue;
/// `_why` documents the reason at the call site.
fn error(_why: &str) -> ErrorStack {
    ErrorStack::get()
}

/// Whether `key` is a key of parameter set `alg`.
pub fn is<T>(alg: Algorithm, key: &PKeyRef<T>) -> bool {
    // SAFETY: `key` is a live EVP_PKEY and the name a 'static C string.
    unsafe { EVP_PKEY_is_a(key.as_ptr(), alg.name.as_ptr()) == 1 }
}

/// The parameter set of `key`, if it is one of [`Algorithm::ALL`].
pub fn algorithm_of<T>(key: &PKeyRef<T>) -> Option<Algorithm> {
    Algorithm::ALL.into_iter().find(|a| is(*a, key))
}

fn require<T>(alg: Algorithm, key: &PKeyRef<T>) -> Result<(), ErrorStack> {
    if is(alg, key) {
        Ok(())
    } else {
        Err(error("key is not of the requested parameter set"))
    }
}

/// Generate a new key pair with the provider's DRBG.
pub fn generate(alg: Algorithm) -> Result<PKey<Private>, ErrorStack> {
    let ctx = Ctx::from_name(alg)?;
    let mut pkey: *mut EVP_PKEY = null_mut();
    // SAFETY: ctx is live; EVP_PKEY_generate stores a new key the caller
    // owns in `pkey` on success.
    unsafe {
        cvt(EVP_PKEY_keygen_init(ctx.0))?;
        cvt(EVP_PKEY_generate(ctx.0, &mut pkey))?;
        Ok(PKey::from_ptr(cvt_p(pkey)?))
    }
}

/// Derive the key pair from a client-supplied FIPS 203 / FIPS 204 seed
/// (ML-KEM.KeyGen_internal(d, z), ML-DSA.KeyGen_internal(xi)).
pub fn from_seed(alg: Algorithm, seed: &[u8]) -> Result<PKey<Private>, ErrorStack> {
    if alg.seed_len() != Some(seed.len()) {
        return Err(error("seed length does not match the parameter set"));
    }
    let ctx = Ctx::from_name(alg)?;
    let mut pkey: *mut EVP_PKEY = null_mut();
    // SAFETY: the octet-string parameter points at `seed` for the duration
    // of EVP_PKEY_fromdata, which only reads input parameters (the
    // non-const pointer is the OSSL_PARAM layout, not a write).
    unsafe {
        let mut params = [
            OSSL_PARAM_construct_octet_string(
                c"seed".as_ptr(),
                seed.as_ptr() as *mut c_void,
                seed.len(),
            ),
            OSSL_PARAM_construct_end(),
        ];
        cvt(EVP_PKEY_fromdata_init(ctx.0))?;
        cvt(EVP_PKEY_fromdata(
            ctx.0,
            &mut pkey,
            EVP_PKEY_KEYPAIR,
            params.as_mut_ptr(),
        ))?;
        let key = PKey::<Private>::from_ptr(cvt_p(pkey)?);
        require(alg, &key)?;
        Ok(key)
    }
}

/// Import a private key in its FIPS 203/204/205 byte encoding (dk or sk).
/// The provider checks the encoding (ML-KEM: the H(ek) check of FIPS 203
/// section 7.3).
pub fn private_from_raw(alg: Algorithm, bytes: &[u8]) -> Result<PKey<Private>, ErrorStack> {
    openssl::init();
    // SAFETY: the provider copies `bytes`; the name is a 'static C string.
    unsafe {
        let p = EVP_PKEY_new_raw_private_key_ex(
            null_mut(),
            alg.name.as_ptr(),
            null(),
            bytes.as_ptr(),
            bytes.len(),
        );
        let key = PKey::<Private>::from_ptr(cvt_p(p)?);
        require(alg, &key)?;
        Ok(key)
    }
}

/// Import a public key in its FIPS 203/204/205 byte encoding (ek or pk).
/// ML-KEM encapsulation keys are checked (FIPS 203 section 7.2).
pub fn public_from_raw(alg: Algorithm, bytes: &[u8]) -> Result<PKey<Public>, ErrorStack> {
    openssl::init();
    // SAFETY: as for private_from_raw.
    unsafe {
        let p = EVP_PKEY_new_raw_public_key_ex(
            null_mut(),
            alg.name.as_ptr(),
            null(),
            bytes.as_ptr(),
            bytes.len(),
        );
        let key = PKey::<Public>::from_ptr(cvt_p(p)?);
        require(alg, &key)?;
        Ok(key)
    }
}

fn octet_param<T>(key: &PKeyRef<T>, name: &CStr) -> Result<Zeroizing<Vec<u8>>, ErrorStack> {
    let mut len = 0usize;
    // SAFETY: a null buffer asks only for the length; `key` is live.
    unsafe {
        cvt(EVP_PKEY_get_octet_string_param(
            key.as_ptr(),
            name.as_ptr(),
            null_mut(),
            0,
            &mut len,
        ))?;
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    // SAFETY: `buf` has `len` writable bytes; the provider writes at most
    // max_buf_sz bytes and reports the count in `len`.
    unsafe {
        cvt(EVP_PKEY_get_octet_string_param(
            key.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut len,
        ))?;
    }
    buf.truncate(len);
    Ok(buf)
}

/// The public key's FIPS byte encoding (ek or pk).
pub fn raw_public<T: HasPublic>(alg: Algorithm, key: &PKeyRef<T>) -> Result<Vec<u8>, ErrorStack> {
    require(alg, key)?;
    Ok(octet_param(key, c"pub")?.to_vec())
}

/// The private key's FIPS byte encoding (dk or sk).
pub fn raw_private<T: HasPrivate>(
    alg: Algorithm,
    key: &PKeyRef<T>,
) -> Result<Zeroizing<Vec<u8>>, ErrorStack> {
    require(alg, key)?;
    octet_param(key, c"priv")
}

/// The key-generation seed of an ML-KEM or ML-DSA private key, when the
/// key still holds it (a key imported from its expanded encoding does not).
pub fn seed<T: HasPrivate>(alg: Algorithm, key: &PKeyRef<T>) -> Option<Zeroizing<Vec<u8>>> {
    alg.seed_len()?;
    require(alg, key).ok()?;
    match octet_param(key, c"seed") {
        Ok(seed) if Some(seed.len()) == alg.seed_len() => Some(seed),
        _ => {
            // Absent: drop the error the provider queued.
            let _ = ErrorStack::get();
            None
        }
    }
}

/// ML-KEM.Encaps (FIPS 203 Algorithm 20): returns (ciphertext, shared secret).
pub fn encapsulate<T: HasPublic>(
    alg: Algorithm,
    key: &PKeyRef<T>,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), ErrorStack> {
    if alg.family != Family::MlKem {
        return Err(error("not a KEM"));
    }
    require(alg, key)?;
    let ctx = Ctx::from_pkey(key)?;
    let (mut clen, mut slen) = (0usize, 0usize);
    // SAFETY: null output buffers ask for the lengths only.
    unsafe {
        cvt(EVP_PKEY_encapsulate_init(ctx.0, null()))?;
        cvt(EVP_PKEY_encapsulate(
            ctx.0,
            null_mut(),
            &mut clen,
            null_mut(),
            &mut slen,
        ))?;
    }
    let mut ciphertext = vec![0u8; clen];
    let mut secret = Zeroizing::new(vec![0u8; slen]);
    // SAFETY: both buffers have the lengths the provider reported and stay
    // live for the call; the provider updates the lengths it wrote.
    unsafe {
        cvt(EVP_PKEY_encapsulate(
            ctx.0,
            ciphertext.as_mut_ptr(),
            &mut clen,
            secret.as_mut_ptr(),
            &mut slen,
        ))?;
    }
    ciphertext.truncate(clen);
    secret.truncate(slen);
    Ok((ciphertext, secret))
}

/// ML-KEM.Decaps (FIPS 203 Algorithm 21). A ciphertext of the right length
/// that was not produced for this key yields the implicit-rejection secret
/// (FIPS 203 section 6.3), not an error; a wrong length is an error.
pub fn decapsulate<T: HasPrivate>(
    alg: Algorithm,
    key: &PKeyRef<T>,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ErrorStack> {
    if alg.family != Family::MlKem {
        return Err(error("not a KEM"));
    }
    require(alg, key)?;
    let ctx = Ctx::from_pkey(key)?;
    let mut slen = 0usize;
    // SAFETY: a null output buffer asks for the length only; `ciphertext`
    // is read for the given length.
    unsafe {
        cvt(EVP_PKEY_decapsulate_init(ctx.0, null()))?;
        cvt(EVP_PKEY_decapsulate(
            ctx.0,
            null_mut(),
            &mut slen,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
    }
    let mut secret = Zeroizing::new(vec![0u8; slen]);
    // SAFETY: `secret` has the reported length and stays live for the call.
    unsafe {
        cvt(EVP_PKEY_decapsulate(
            ctx.0,
            secret.as_mut_ptr(),
            &mut slen,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
    }
    secret.truncate(slen);
    Ok(secret)
}

/// Signature-context parameters; the ints live in this struct so the
/// OSSL_PARAM array that points at them cannot outlive them.
struct SignatureParams<'a> {
    options: SignatureOptions<'a>,
    deterministic: c_int,
    mu: c_int,
}
impl<'a> SignatureParams<'a> {
    fn new(alg: Algorithm, options: SignatureOptions<'a>) -> Result<Self, ErrorStack> {
        if alg.family == Family::MlKem
            || options.context.len() > 255
            || options.external_mu && alg.family != Family::MlDsa
        {
            return Err(error("unsupported signature options"));
        }
        Ok(SignatureParams {
            options,
            deterministic: c_int::from(options.deterministic),
            mu: c_int::from(options.external_mu),
        })
    }
    /// Run `f` with the OSSL_PARAM array for these options.
    fn with<R>(&mut self, sign: bool, f: impl FnOnce(*const OSSL_PARAM) -> R) -> R {
        let mut params = Vec::with_capacity(4);
        // SAFETY: each entry points at data in `self` (the context bytes,
        // borrowed for 'a, and the ints), which outlives `params`; the
        // provider only reads input parameters during `f`.
        unsafe {
            params.push(OSSL_PARAM_construct_octet_string(
                c"context-string".as_ptr(),
                self.options.context.as_ptr() as *mut c_void,
                self.options.context.len(),
            ));
            if sign && self.options.deterministic {
                params.push(OSSL_PARAM_construct_int(
                    c"deterministic".as_ptr(),
                    &mut self.deterministic,
                ));
            }
            if self.options.external_mu {
                params.push(OSSL_PARAM_construct_int(c"mu".as_ptr(), &mut self.mu));
            }
            params.push(OSSL_PARAM_construct_end());
        }
        f(params.as_ptr())
    }
}

fn fetch_signature(alg: Algorithm) -> Result<Signature, ErrorStack> {
    // SAFETY: 'static name; default library context and properties.
    let p = unsafe { EVP_SIGNATURE_fetch(null_mut(), alg.name.as_ptr(), null()) };
    Ok(Signature(cvt_p(p)?))
}

/// ML-DSA.Sign (FIPS 204 Algorithm 2) or SLH-DSA.Sign (FIPS 205
/// Algorithm 22), the pure external interface.
pub fn sign<T: HasPrivate>(
    alg: Algorithm,
    key: &PKeyRef<T>,
    message: &[u8],
    options: SignatureOptions<'_>,
) -> Result<Vec<u8>, ErrorStack> {
    require(alg, key)?;
    let mut params = SignatureParams::new(alg, options)?;
    let signature = fetch_signature(alg)?;
    let ctx = Ctx::from_pkey(key)?;
    params.with(true, |p| {
        // SAFETY: ctx and the fetched algorithm are live; `p` is a
        // terminated parameter array valid for this closure.
        unsafe { cvt(EVP_PKEY_sign_message_init(ctx.0, signature.0, p)) }
    })?;
    let mut len = 0usize;
    // SAFETY: a null signature buffer asks for the maximum length only.
    unsafe {
        cvt(EVP_PKEY_sign(
            ctx.0,
            null_mut(),
            &mut len,
            message.as_ptr(),
            message.len(),
        ))?;
    }
    let mut out = vec![0u8; len];
    // SAFETY: `out` has `len` writable bytes; the provider reports the
    // length it wrote.
    unsafe {
        cvt(EVP_PKEY_sign(
            ctx.0,
            out.as_mut_ptr(),
            &mut len,
            message.as_ptr(),
            message.len(),
        ))?;
    }
    out.truncate(len);
    Ok(out)
}

/// ML-DSA.Verify (FIPS 204 Algorithm 3) or SLH-DSA.Verify (FIPS 205
/// Algorithm 24). A malformed or wrong signature is `Ok(false)`; only a
/// setup failure (wrong key, unusable options) is an error.
pub fn verify<T: HasPublic>(
    alg: Algorithm,
    key: &PKeyRef<T>,
    message: &[u8],
    signature: &[u8],
    options: SignatureOptions<'_>,
) -> Result<bool, ErrorStack> {
    require(alg, key)?;
    let mut params = SignatureParams::new(alg, options)?;
    let algorithm = fetch_signature(alg)?;
    let ctx = Ctx::from_pkey(key)?;
    params.with(false, |p| {
        // SAFETY: as in `sign`.
        unsafe { cvt(EVP_PKEY_verify_message_init(ctx.0, algorithm.0, p)) }
    })?;
    // SAFETY: both buffers are read for their lengths.
    let r = unsafe {
        EVP_PKEY_verify(
            ctx.0,
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
        )
    };
    if r != 1 {
        // Drop whatever the provider queued for the rejected signature.
        let _ = ErrorStack::get();
    }
    Ok(r == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_parameter_set_generates_round_trips_and_reports_its_name() {
        for alg in Algorithm::ALL {
            let key = generate(alg).unwrap();
            assert!(is(alg, &key), "{}", alg.name());
            assert_eq!(algorithm_of(&key), Some(alg));
            let public = raw_public(alg, &key).unwrap();
            let private = raw_private(alg, &key).unwrap();
            let again = private_from_raw(alg, &private).unwrap();
            assert_eq!(raw_public(alg, &again).unwrap(), public);
            let pk = public_from_raw(alg, &public).unwrap();
            assert!(pk.public_eq(&key));
            // PKCS#8 and SubjectPublicKeyInfo through the safe crate.
            let der = key.private_key_to_pkcs8().unwrap();
            let back = PKey::private_key_from_pkcs8(&der).unwrap();
            assert_eq!(algorithm_of(&back), Some(alg));
            let spki = key.public_key_to_der().unwrap();
            let back = PKey::public_key_from_der(&spki).unwrap();
            assert_eq!(raw_public(alg, &back).unwrap(), public);
            // Another parameter set's name is refused.
            let other = Algorithm::ALL
                .into_iter()
                .find(|a| *a != alg && a.family == alg.family)
                .unwrap();
            assert!(raw_public(other, &key).is_err());
        }
    }

    #[test]
    fn kem_round_trip_and_implicit_rejection() {
        for alg in [
            Algorithm::ML_KEM_512,
            Algorithm::ML_KEM_768,
            Algorithm::ML_KEM_1024,
        ] {
            let key = generate(alg).unwrap();
            let pk = public_from_raw(alg, &raw_public(alg, &key).unwrap()).unwrap();
            let (ct, ss) = encapsulate(alg, &pk).unwrap();
            assert_eq!(ss.len(), 32);
            assert_eq!(decapsulate(alg, &key, &ct).unwrap(), ss);
            let mut tampered = ct.clone();
            tampered[0] ^= 1;
            let rejected = decapsulate(alg, &key, &tampered).unwrap();
            assert_ne!(rejected, ss);
            assert!(decapsulate(alg, &key, &ct[1..]).is_err());
        }
        let dsa = generate(Algorithm::ML_DSA_44).unwrap();
        assert!(encapsulate(Algorithm::ML_DSA_44, &dsa).is_err());
    }

    #[test]
    fn seeded_generation_is_reproducible() {
        let xi = [7u8; 32];
        let a = from_seed(Algorithm::ML_DSA_65, &xi).unwrap();
        let b = from_seed(Algorithm::ML_DSA_65, &xi).unwrap();
        assert!(a.public_eq(&b));
        assert_eq!(
            seed(Algorithm::ML_DSA_65, &a).unwrap().as_slice(),
            &[7u8; 32]
        );
        assert!(from_seed(Algorithm::ML_DSA_65, &[0; 31]).is_err());
        assert!(from_seed(Algorithm::SLH_DSA_SHA2_128F, &[0; 48]).is_err());
        let kem = from_seed(Algorithm::ML_KEM_768, &[9u8; 64]).unwrap();
        assert!(seed(Algorithm::ML_KEM_768, &kem).is_some());
        // An expanded-key import has no seed.
        let expanded = private_from_raw(
            Algorithm::ML_KEM_768,
            &raw_private(Algorithm::ML_KEM_768, &kem).unwrap(),
        )
        .unwrap();
        assert!(seed(Algorithm::ML_KEM_768, &expanded).is_none());
    }

    #[test]
    fn signatures_verify_and_reject_tampering_and_context_changes() {
        for alg in [Algorithm::ML_DSA_65, Algorithm::SLH_DSA_SHAKE_128F] {
            let key = generate(alg).unwrap();
            let pk = public_from_raw(alg, &raw_public(alg, &key).unwrap()).unwrap();
            let options = SignatureOptions {
                context: b"ctx",
                ..Default::default()
            };
            let sig = sign(alg, &key, b"message", options).unwrap();
            assert!(verify(alg, &pk, b"message", &sig, options).unwrap());
            assert!(!verify(alg, &pk, b"messagf", &sig, options).unwrap());
            assert!(!verify(alg, &pk, b"message", &sig, SignatureOptions::default()).unwrap());
            let mut bad = sig.clone();
            bad[3] ^= 0x40;
            assert!(!verify(alg, &pk, b"message", &bad, options).unwrap());
            assert!(!verify(alg, &pk, b"message", &sig[1..], options).unwrap());
            let det = SignatureOptions {
                deterministic: true,
                ..options
            };
            assert_eq!(
                sign(alg, &key, b"m", det).unwrap(),
                sign(alg, &key, b"m", det).unwrap()
            );
            let long = [0u8; 256];
            let too_long = SignatureOptions {
                context: &long,
                ..Default::default()
            };
            assert!(sign(alg, &key, b"m", too_long).is_err());
        }
        let slh = generate(Algorithm::SLH_DSA_SHA2_128F).unwrap();
        let mu = SignatureOptions {
            external_mu: true,
            ..Default::default()
        };
        assert!(sign(Algorithm::SLH_DSA_SHA2_128F, &slh, &[0; 64], mu).is_err());
        let kem = generate(Algorithm::ML_KEM_512).unwrap();
        assert!(
            sign(
                Algorithm::ML_KEM_512,
                &kem,
                b"m",
                SignatureOptions::default()
            )
            .is_err()
        );
    }
}
