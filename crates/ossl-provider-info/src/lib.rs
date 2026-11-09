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

//! An OpenSSL provider's own description: the `OSSL_PROVIDER_get_params`
//! call for the core parameters "name", "version", "buildinfo" and "status"
//! (OpenSSL 3 `provider-base(7)`, "Provider parameters").
//!
//! The safe `openssl` crate has no binding for this call and the server
//! crate forbids `unsafe`, so this crate holds the one audited FFI wrapper,
//! [`provider_info`]. Nothing else here is unsafe. It only reads: it never
//! loads, unloads or configures a provider.
use foreign_types::ForeignTypeRef;
use openssl::error::ErrorStack;
use openssl::provider::ProviderRef;
use openssl_sys::{OSSL_PARAM, OSSL_PROVIDER};
use std::ffi::{CStr, c_char, c_int};

/// What a provider reports about itself. `None` means the provider does not
/// answer that parameter (each is optional in `provider-base(7)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderInfo {
    /// "name": the provider's own name, such as
    /// "Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider".
    pub name: Option<String>,
    /// "version": the provider version, such as "3.0.7-cda111b5812c30d4".
    pub version: Option<String>,
    /// "buildinfo": the provider's build information string.
    pub build_info: Option<String>,
    /// "status": 1 while the provider is running, 0 once it has entered its
    /// error state (for a FIPS provider: a failed self-test).
    pub status: Option<i32>,
}

// Declared here because openssl-sys 0.9 does not declare them. Signatures as
// in OpenSSL 3.0 <openssl/provider.h> and <openssl/params.h>; libcrypto is
// linked through openssl-sys.
unsafe extern "C" {
    fn OSSL_PROVIDER_get_params(prov: *const OSSL_PROVIDER, params: *mut OSSL_PARAM) -> c_int;
    fn OSSL_PARAM_construct_utf8_ptr(
        key: *const c_char,
        buf: *mut *mut c_char,
        bsize: usize,
    ) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> OSSL_PARAM;
}

/// Ask `provider` for its name, version, build information and status.
///
/// Fails with OpenSSL's error stack if the provider refuses the request.
pub fn provider_info(provider: &ProviderRef) -> Result<ProviderInfo, ErrorStack> {
    // Output slots. The provider stores a pointer to its own string in each
    // UTF-8 pointer slot and the status in `status`.
    let mut name: *mut c_char = std::ptr::null_mut();
    let mut version: *mut c_char = std::ptr::null_mut();
    let mut build_info: *mut c_char = std::ptr::null_mut();
    let mut status: c_int = 0;
    // SAFETY: the constructors only build OSSL_PARAM values that record the
    // key and the output pointer; they dereference nothing. The keys are
    // 'static C strings. The output slots are locals that outlive `params`
    // and are not moved or otherwise accessed until the call below returns.
    let mut params = unsafe {
        [
            OSSL_PARAM_construct_utf8_ptr(c"name".as_ptr(), &raw mut name, 0),
            OSSL_PARAM_construct_utf8_ptr(c"version".as_ptr(), &raw mut version, 0),
            OSSL_PARAM_construct_utf8_ptr(c"buildinfo".as_ptr(), &raw mut build_info, 0),
            OSSL_PARAM_construct_int(c"status".as_ptr(), &raw mut status),
            openssl_sys::OSSL_PARAM_construct_end(),
        ]
    };
    // SAFETY: `provider` is a live OSSL_PROVIDER for the duration of the
    // borrow, and `params` is an array terminated by OSSL_PARAM_END whose
    // entries point at the slots above. The provider writes only into those
    // slots: a pointer for UTF-8 pointer parameters, an int for "status".
    let ok = unsafe { OSSL_PROVIDER_get_params(provider.as_ptr(), params.as_mut_ptr()) };
    if ok != 1 {
        return Err(ErrorStack::get());
    }
    // SAFETY: a parameter the provider set (OSSL_PARAM_modified) holds what
    // the provider wrote: for the string parameters, null or a pointer to a
    // NUL-terminated string the provider owns, which stays valid while the
    // provider is loaded (`provider` is borrowed throughout); it is copied
    // before returning. An unset parameter is not read.
    unsafe {
        let set = |p: &OSSL_PARAM| openssl_sys::OSSL_PARAM_modified(p) == 1;
        let text = |p: &OSSL_PARAM, s: *mut c_char| {
            (set(p) && !s.is_null()).then(|| CStr::from_ptr(s).to_string_lossy().into_owned())
        };
        Ok(ProviderInfo {
            name: text(&params[0], name),
            version: text(&params[1], version),
            build_info: text(&params[2], build_info),
            status: set(&params[3]).then_some(status),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::lib_ctx::LibCtx;
    use openssl::provider::Provider;

    /// The upstream "default" and "base" providers, loaded into a private
    /// library context so the process-wide default context is untouched.
    #[test]
    fn reads_the_core_parameters_of_the_built_in_providers() {
        let ctx = LibCtx::new().unwrap();
        let library = openssl::version::number();
        // OPENSSL_VERSION_NUMBER is 0xMNN00PP0L; the built-in providers report
        // the library version as their own.
        let expected = format!(
            "{}.{}.{}",
            library >> 28,
            (library >> 20) & 0xff,
            (library >> 4) & 0xff
        );
        for (id, name) in [
            ("default", "OpenSSL Default Provider"),
            ("base", "OpenSSL Base Provider"),
        ] {
            let provider = Provider::load(Some(&ctx), id).unwrap();
            let info = provider_info(&provider).unwrap();
            assert_eq!(info.name.as_deref(), Some(name), "{info:?}");
            assert_eq!(info.status, Some(1), "{info:?}");
            let version = info.version.clone().unwrap();
            assert!(version.starts_with(&expected), "{version} vs {expected}");
            assert!(info.build_info.is_some_and(|b| !b.is_empty()), "{id}");
        }
    }

    /// Repeated reads give the same answer and leave the provider usable.
    #[test]
    fn reading_is_repeatable_and_has_no_side_effects() {
        let ctx = LibCtx::new().unwrap();
        let provider = Provider::load(Some(&ctx), "default").unwrap();
        let first = provider_info(&provider).unwrap();
        for _ in 0..100 {
            assert_eq!(provider_info(&provider).unwrap(), first);
        }
        openssl::md::Md::fetch(Some(&ctx), "SHA2-256", None).unwrap();
    }
    // A FIPS provider needs its configuration, which a private library
    // context cannot load through the safe binding; tests/fips_mode.rs reads
    // one through `keytend-kmip-server --fips fips-check`.
}
