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

//! Create Key Pair attributes that "SHALL contain the same value for both
//! Private and Public Key": Cryptographic Algorithm, Cryptographic Length,
//! Cryptographic Domain Parameters and Cryptographic Parameters (1.0 Table 112,
//! 1.1 Table 126, 1.2 Table 141, 1.3 Table 152, 1.4 Table 168, 2.0 Table 176,
//! 2.1 Table 191).
//!
//! Values given for both keys must agree, or the request fails with Invalid
//! Field. A value given for one key only is applied to both, so the resulting
//! keys carry the same value as the tables require.
use super::*;

const SHARED: [u32; 4] = [
    CRYPTOGRAPHIC_ALGORITHM,
    CRYPTOGRAPHIC_LENGTH,
    CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
    CRYPTOGRAPHIC_PARAMETERS,
];

fn instances(attrs: &[Node], tag: u32) -> Vec<Node> {
    attrs.iter().filter(|a| a.tag == tag).cloned().collect()
}
fn same(a: &[Node], b: &[Node]) -> bool {
    a.len() == b.len() && a.iter().all(|n| b.contains(n)) && b.iter().all(|n| a.contains(n))
}

/// Make the shared attributes of the two key templates agree.
pub(super) fn reconcile(private: &mut Vec<Node>, public: &mut Vec<Node>) -> R<()> {
    for tag in SHARED {
        let mine = instances(private, tag);
        let theirs = instances(public, tag);
        match (mine.is_empty(), theirs.is_empty()) {
            (false, false) if !same(&mine, &theirs) => {
                return Err(fail(
                    7,
                    "Create Key Pair attributes differ between the private and public key",
                ));
            }
            (false, true) => public.extend(mine),
            (true, false) => private.extend(theirs),
            _ => {}
        }
    }
    Ok(())
}
