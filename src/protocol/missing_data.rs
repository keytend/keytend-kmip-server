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

//! The versioned Result Reason for a request that lacks data the operation
//! needs (an omitted Unique Identifier with an empty ID Placeholder, absent
//! Join Split Key parts, a missing derivation source and the like).
//!
//! KMIP 1.x reports Missing Data. KMIP 2.0, 2.1 and draft 3.0 keep the
//! enumeration value, but no per-operation error table lists it (for example
//! 2.1 Table 222 Get, Table 307 Re-key, Table 312 Re-key Key Pair), while every
//! table lists Invalid Field. The failure is rewritten once in
//! `Engine::execute`, so the same condition reads Invalid Field there, as a
//! missing REQUIRED field already does.
use super::*;

const MISSING_DATA: u32 = 6;
const INVALID_FIELD: u32 = 7;

/// Rewrite Missing Data to the reason the 2.x error tables give.
pub(super) fn versioned(v: Version, e: Failure) -> Failure {
    if v.0 >= 2 && e.reason == MISSING_DATA {
        Failure {
            reason: INVALID_FIELD,
            ..e
        }
    } else {
        e
    }
}
