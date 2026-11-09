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

//! The KMIP PKCS#11 operation (2.0 section 6.1.35, 2.1 section 6.1.37) with
//! the Profiles 2.0/2.1 section 5.18.1 encoding, limited to the general-purpose
//! functions C_Initialize, C_Finalize and C_GetInfo. Every other function of
//! the V3.0 interface answers CKR_FUNCTION_NOT_SUPPORTED, as PKCS#11 3.0 base
//! section 5 requires of a library stub. There are no slots, tokens, sessions
//! or objects, so this is not a PKCS#11 bridge to managed objects.
//!
//! The KMIP Correlation Value is the handle of one initialized library
//! instance. It is server random, owner scoped, kept only in memory (a restart
//! finalizes every instance) and bounded per principal. C_Initialize returns
//! it; only draft 3.0 echoes it in C_GetInfo and C_Finalize responses.
use super::*;

/// 1-based offsets in CK_FUNCTION_LIST_3_0 (KMIP 2.1 section 11.38).
const C_INITIALIZE: u32 = 1;
const C_FINALIZE: u32 = 2;
const C_GET_INFO: u32 = 3;
/// C_MessageVerifyFinal, the last of the 92 functions of the 3.0 list.
const LAST_FUNCTION: u32 = 92;
/// CK_RV values from the PKCS#11 3.0 pkcs11t.h.
const CKR_OK: u32 = 0x00;
const CKR_FUNCTION_NOT_SUPPORTED: u32 = 0x54;
const CKR_CRYPTOKI_NOT_INITIALIZED: u32 = 0x190;
const CKR_CRYPTOKI_ALREADY_INITIALIZED: u32 = 0x191;
/// Profiles 5.18.1: "The version SHALL be set to 1".
const ENCODING_VERSION: u8 = 1;
/// The name of the standard PKCS#11 3.0 interface (C_GetInterface "PKCS 11").
const INTERFACE: &str = "PKCS 11";
const MAX_PER_OWNER: usize = 16;
const IDLE_SECONDS: i64 = 900;
const HANDLE_BYTES: usize = 16;

#[derive(Clone, Default)]
pub(crate) struct Libraries {
    open: Vec<Library>,
}
#[derive(Clone)]
struct Library {
    owner: String,
    handle: Vec<u8>,
    used: i64,
}
impl Libraries {
    pub(super) fn purge(&mut self) {
        let cutoff = now() - IDLE_SECONDS;
        self.open.retain(|l| l.used >= cutoff);
    }
    fn find(&mut self, owner: &str, handle: Option<&[u8]>) -> Option<usize> {
        let handle = handle?;
        self.open
            .iter()
            .position(|l| l.owner == owner && l.handle == handle)
    }
}

/// CK_INFO (PKCS#11 3.0 base section 3.1) in the Profiles 5.18.1 encoding:
/// CK_VERSION as two bytes, the two CK_UTF8CHAR[32] fields blank padded and
/// CK_FLAGS (a CK_ULONG that is not a count) as 8 bytes big-endian.
/// cryptokiVersion is 3.0: "the value of cryptokiVersion should match the
/// version of this specification", and KMIP 2.1 section 6.1.37 makes the V3.0
/// interface the default. Flags "MUST be zero for this version".
/// libraryVersion is this server's crate version.
pub(super) fn ck_info() -> Vec<u8> {
    fn padded(text: &str) -> [u8; 32] {
        let mut field = [b' '; 32];
        field[..text.len()].copy_from_slice(text.as_bytes());
        field
    }
    let mut out = vec![3, 0];
    out.extend(padded("Keytend"));
    out.extend(0u64.to_be_bytes());
    out.extend(padded("Keytend PKCS#11 over KMIP"));
    out.push(env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0));
    out.push(env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0));
    out
}

impl Engine {
    pub(super) fn pkcs11(&mut self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        no_fields(
            p,
            &[
                PKCS_11_INTERFACE,
                PKCS_11_FUNCTION,
                CORRELATION_VALUE,
                PKCS_11_INPUT_PARAMETERS,
            ],
        )?;
        let interface = p.get(PKCS_11_INTERFACE);
        if let Some(name) = interface
            && name.string()? != INTERFACE
        {
            return Err(fail(0x47, "PKCS#11 interface is unknown or unavailable"));
        }
        // An Integer names a vendor function; none are in the interface.
        let function = match p.required(PKCS_11_FUNCTION)?.value {
            Value::Enumeration(f @ 1..=LAST_FUNCTION) => f,
            Value::Enumeration(_) | Value::Integer(_) => {
                return Err(fail(0x46, "PKCS#11 function is not in the interface"));
            }
            _ => return Err(fail(7, "Invalid PKCS#11 Function")),
        };
        let handle = p
            .get(CORRELATION_VALUE)
            .map(Node::byte_string)
            .transpose()?
            .map(<[u8]>::to_vec);
        let input = p
            .get(PKCS_11_INPUT_PARAMETERS)
            .map(Node::byte_string)
            .transpose()?;
        let libraries = &mut self.side.pkcs11;
        libraries.purge();
        let found = libraries.find(owner, handle.as_deref());
        // Correlation Value (docs/interpretations.md): 2.0 and 2.1
        // return the Correlation Value only in the C_Initialize response, as
        // the OASIS traces PKCS11-M-1-20/21 do; draft 3.0 also echoes the
        // named live instance in the C_GetInfo and C_Finalize responses
        // (PKCS11-M-1-30). Other functions never return it.
        let echo = v.0 >= 3 && matches!(function, C_GET_INFO | C_FINALIZE);
        let mut live = found
            .filter(|_| echo)
            .map(|index| libraries.open[index].handle.clone());
        let mut output = None;
        let code = match function {
            C_INITIALIZE => {
                // Profiles 5.18.1: "C_Initialize passes a single BYTE
                // parameter that encodes the version of this encoding."
                if input != Some(&[ENCODING_VERSION][..]) {
                    return Err(fail(0x45, "Unsupported PKCS#11 encoding version"));
                }
                if let Some(index) = found {
                    libraries.open[index].used = now();
                    live = Some(libraries.open[index].handle.clone());
                    CKR_CRYPTOKI_ALREADY_INITIALIZED
                } else {
                    let mine = libraries.open.iter().filter(|l| l.owner == owner).count();
                    if mine >= MAX_PER_OWNER
                        && let Some(oldest) = libraries
                            .open
                            .iter()
                            .enumerate()
                            .filter(|(_, l)| l.owner == owner)
                            .min_by_key(|(_, l)| l.used)
                            .map(|(i, _)| i)
                    {
                        libraries.open.remove(oldest);
                    }
                    let handle = crypto::random(HANDLE_BYTES)
                        .map_err(|_| fail(0x100, "Random source failed"))?
                        .to_vec();
                    libraries.open.push(Library {
                        owner: owner.to_owned(),
                        handle: handle.clone(),
                        used: now(),
                    });
                    live = Some(handle);
                    CKR_OK
                }
            }
            // C_Finalize "does not pass through its parameter"; C_GetInfo
            // has only an output.
            C_FINALIZE | C_GET_INFO if input.is_some() => {
                return Err(fail(0x45, "PKCS#11 function takes no input parameters"));
            }
            C_FINALIZE => match found {
                Some(index) => {
                    libraries.open.remove(index);
                    CKR_OK
                }
                None => CKR_CRYPTOKI_NOT_INITIALIZED,
            },
            C_GET_INFO => match found {
                Some(index) => {
                    libraries.open[index].used = now();
                    output = Some(ck_info());
                    CKR_OK
                }
                None => CKR_CRYPTOKI_NOT_INITIALIZED,
            },
            _ => CKR_FUNCTION_NOT_SUPPORTED,
        };
        let mut out = vec![];
        if let Some(name) = interface {
            out.push(name.clone());
        }
        out.push(Node::enumeration(PKCS_11_FUNCTION, function));
        if let Some(handle) = live {
            out.push(Node::bytes(CORRELATION_VALUE, handle));
        }
        if let Some(output) = output {
            out.push(Node::bytes(PKCS_11_OUTPUT_PARAMETERS, output));
        }
        out.push(Node::enumeration(PKCS_11_RETURN_CODE, code));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ck_info_layout_follows_the_profile_encoding() {
        let info = ck_info();
        // 2 + 32 + 8 + 32 + 2 bytes.
        assert_eq!(info.len(), 76);
        assert_eq!(&info[..2], &[3, 0]);
        assert_eq!(&info[2..34], b"Keytend                         ");
        assert!(info[12..34].iter().all(|b| *b == b' '));
        assert_eq!(&info[34..42], &[0; 8]);
        assert!(info[42..74].starts_with(b"Keytend PKCS#11 over KMIP"));
        assert!(info[42 + 28..74].iter().all(|b| *b == b' '));
    }
}
