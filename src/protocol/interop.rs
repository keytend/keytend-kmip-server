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

//! The Interop operation (2.0 section 6.1.25, 2.1 section 6.1.26, draft 3.0
//! section 6.1.32), offered only in interop test mode
//! (docs/interpretations.md#interop and docs/configuration.md).
//!
//! The text: "This operation informs the server about the status if interop
//! tests. It SHALL NOT be available in a production server. The Interop
//! Operation uses three Interop Functions (Begin, End and Reset)." The request
//! carries an Interop Function and an Interop Identifier and the response
//! payload is empty. The text gives the functions no further effect, so:
//!
//! - Begin records the caller's current test identifier and End clears it;
//!   both are logged. Neither checks the sequence, which the text does not
//!   define.
//! - Reset clears only the calling principal's record.
//! - Draft 3.0 reserves the identifier "*" for a cleanup of "the currently
//!   authenticated user". That would delete the caller's objects, which this
//!   server does not do on request of a test control operation, so it is
//!   refused with Feature Not Supported (Table 349) rather than ignored.
//!
//! The mode is off by default; Query lists Interop only when it is on.
use super::*;

/// The Interop operation (2.1 section 11.48, value 0x34).
pub(super) const INTEROP: u32 = 0x34;
/// Re-Provision (2.1 section 11.48, value 0x35), offered only with
/// `--provisioning-ca`.
const RE_PROVISION: u32 = 0x35;
/// Interop Function values (2.1 section 11.27).
const BEGIN: u32 = 1;
const END: u32 = 2;
const RESET: u32 = 3;
/// Bounds on the in-memory record.
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_PRINCIPALS: usize = 1024;

/// The test identifier each principal has begun, kept only in memory.
#[derive(Clone, Default)]
pub(crate) struct Tests {
    current: std::collections::BTreeMap<String, String>,
}

pub(super) fn defined(v: Version) -> bool {
    v >= Version(2, 0)
}

impl Engine {
    /// Offer the test-only Interop operation. Never enable it in production:
    /// the specification says it "SHALL NOT be available in a production
    /// server".
    pub fn with_interop_test_mode(mut self, enabled: bool) -> Self {
        self.interop_test_mode = enabled;
        self
    }
    /// Operations this server performs in version `v`, including Interop
    /// when test mode is on and Re-Provision (2.0+) with a provisioning CA
    /// (provisioning.rs).
    pub(super) fn offered_operations(&self, v: Version) -> Vec<u32> {
        let mut ops = version_ops(v);
        if self.interop_test_mode && defined(v) {
            ops.push(INTEROP);
            ops.sort();
        }
        if self.provisioning.is_some() && v.0 >= 2 {
            ops.push(RE_PROVISION);
            ops.sort();
        }
        ops.retain(|op| super::fips_policy::offers_operation(self.fips, *op));
        ops
    }
    pub(super) fn interop(&mut self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        no_fields(p, &[INTEROP_FUNCTION, INTEROP_IDENTIFIER])?;
        let function = p.required(INTEROP_FUNCTION)?;
        if !matches!(function.value, Value::Enumeration(_)) {
            return Err(fail(7, "Interop Function must be an Enumeration"));
        }
        let function = function.number()?;
        let identifier = p.required(INTEROP_IDENTIFIER)?.string()?;
        if identifier.is_empty() || identifier.len() > MAX_IDENTIFIER_BYTES {
            return Err(fail(7, "Invalid Interop Identifier"));
        }
        if v.0 >= 3 && identifier == "*" {
            return Err(fail(8, "Interop cleanup is not supported"));
        }
        let tests = &mut self.side.interop.current;
        match function {
            BEGIN => {
                if !tests.contains_key(owner) && tests.len() >= MAX_PRINCIPALS {
                    return Err(server_limit(v, "Too many interop tests in progress"));
                }
                tests.insert(owner.to_owned(), identifier.to_owned());
            }
            END | RESET => {
                tests.remove(owner);
            }
            _ => return Err(fail(7, "Unknown Interop Function")),
        }
        tracing::info!(%owner, function, test = %identifier, "KMIP Interop");
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interop_is_offered_only_in_test_mode_from_2_0() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master.key");
        std::fs::write(&key, [7u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&dir.path().join("db.sqlite"), &key).unwrap();
        let engine = Engine::new(store, true);
        for v in Version::supported(true) {
            assert!(!engine.offered_operations(v).contains(&INTEROP));
        }
        let engine = engine.with_interop_test_mode(true);
        for v in Version::supported(true) {
            assert_eq!(engine.offered_operations(v).contains(&INTEROP), v.0 >= 2);
        }
    }
}
