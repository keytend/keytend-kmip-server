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

//! The versioned Result Reason for a Unique Identifier that names no object
//! the caller may use.
//!
//! Every lookup reports the same failure for a missing object and for another
//! principal's object, so ownership stays hidden. KMIP 1.x has only Item Not
//! Found. KMIP 2.0, 2.1 and draft 3.0 add Object Not Found (0x37), and the
//! per-operation error tables (2.1 Table 166 Activate, Table 210 Destroy,
//! Table 222 Get, Table 225 Get Attributes and the like; 2.0 Tables 151, 195,
//! 207, 210) list it, so the failure is rewritten once in `Engine::execute`.
use super::*;

const MESSAGE: &str = "Object not found";

/// The single failure for an identifier that names no accessible object.
pub(super) fn object() -> Failure {
    fail(1, MESSAGE)
}

/// True for the failure `object()` builds.
pub(super) fn is_object(e: &Failure) -> bool {
    e.reason == 1 && e.message == MESSAGE
}

/// 2.x and draft 3.0 operations whose error tables name Item Not Found and
/// not Object Not Found: Adjust Attribute (2.1 Table 172), Certify (Table 181)
/// and Create Split Key (Table 195); the same in 2.0 and draft 3.0.
const ITEM_NOT_FOUND_OPERATIONS: [u32; 3] = [6, 40, 48];

/// Rewrite the 1.x reason to the reason the version's error table gives.
pub(super) fn versioned(v: Version, op: u32, e: Failure) -> Failure {
    if v.0 >= 2 && is_object(&e) && !ITEM_NOT_FOUND_OPERATIONS.contains(&op) {
        Failure { reason: 0x37, ..e }
    } else {
        e
    }
}
