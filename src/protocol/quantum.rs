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

//! Protection Level, Protection Period and Quantum Safe (KMIP 2.0 sections
//! 4.42, 4.43 and 4.45; 2.1 the same sections; tables 112-119 in 2.0 and
//! 113-120 in 2.1). Each is single valued, initially set by the client,
//! modifiable and deletable by the client, never set or changed by the server
//! and applies to all objects. They do not exist before KMIP 2.0.
//!
//! Quantum Safe "is a flag to be set to indicate an object is required to be
//! Quantum Safe for the given Protection Period and Protection Level". The
//! specification does not define which objects qualify, so the server policy
//! is: a symmetric key qualifies only with a 256-bit AES, ChaCha20 or
//! ChaCha20-Poly1305 key (the symmetric strength required by NSA CNSA 2.0;
//! Grover's algorithm halves the effective strength of shorter keys).
//! ML-KEM, ML-DSA and SLH-DSA keys (draft 3.0 only, pqc.rs) qualify at NIST
//! Security Category 5 (ML-KEM-1024, ML-DSA-87 and the 256-bit SLH-DSA sets),
//! the post-quantum counterpart of the 256-bit symmetric threshold. Other
//! asymmetric keys, certificates and other objects never qualify: RSA, DSA,
//! DH and EC fall to Shor's algorithm, and the server cannot judge opaque or
//! secret data. The policy
//! accepts any Protection Level and Period for a qualifying key. A request
//! that would leave an object flagged True that does not qualify fails with
//! General Failure, the reason used by Profiles QS-M-2-20/21 for this case.
use super::*;

/// Protection Level enumeration (2.0 table 435, 2.1 table 474).
const HIGH: u32 = 1;
const LOW: u32 = 2;
const AES: u32 = 3;
const CHACHA20: u32 = 28;
const CHACHA20_POLY1305: u32 = 30;

pub(super) fn attribute(tag: u32) -> bool {
    matches!(tag, PROTECTION_LEVEL | PROTECTION_PERIOD | QUANTUM_SAFE)
}

/// Value checks for validate_attrs; the caller has gated the version.
pub(super) fn validate(a: &Node) -> R<()> {
    match (a.tag, &a.value) {
        (PROTECTION_LEVEL, Value::Enumeration(HIGH | LOW)) => Ok(()),
        (PROTECTION_LEVEL, Value::Enumeration(_)) => Err(fail(7, "Unsupported Protection Level")),
        (PROTECTION_PERIOD, Value::Interval(_)) | (QUANTUM_SAFE, Value::Boolean(_)) => Ok(()),
        _ => Err(fail(7, "Invalid quantum safety attribute type")),
    }
}

fn qualifies(obj: &Object) -> bool {
    obj.object_type == 2
        && matches!(obj.algorithm, AES | CHACHA20 | CHACHA20_POLY1305)
        && obj.bits >= 256
        || pqc::security_category(obj) == Some(5)
}

/// Called before an object is stored with client-supplied attributes.
pub(super) fn check(obj: &Object) -> R<()> {
    pqc::check_category(obj)?;
    let required = obj
        .attrs
        .iter()
        .any(|a| a.tag == QUANTUM_SAFE && a.flag().unwrap_or(false));
    if required && !qualifies(obj) {
        return Err(fail(
            0x100,
            "Object is not quantum safe for its Protection Level and Period",
        ));
    }
    Ok(())
}
