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

//! KMIP 1.0 Activation Date at creation (1.0 section 3.17, transition 1).
//!
//! "If, however, the operation that creates or registers the object contains
//! an Activation Date that has already occurred, then the state immediately
//! transitions from Pre-Active to Active. In this case, the server SHALL set
//! the Activation Date attribute to the time when the operation is received,
//! or fail the request [...] depending on server policy."
//!
//! This server takes the first branch: in a 1.0 request, an Activation Date
//! at or before the time the request message was received is replaced by that
//! time before the operation runs. 1.1 and later changed the rule to "the
//! value specified in the request", so their values are kept unchanged.
use super::*;

/// The 1.0 operations that create or register an object.
const OPERATIONS: [u32; 7] = [1, 2, 3, 4, 5, 6, 7];
/// The 1.0 Template-Attribute containers of those operations.
const CONTAINERS: [u32; 4] = [
    TEMPLATE_ATTRIBUTE,
    COMMON_TEMPLATE_ATTRIBUTE,
    PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
    PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
];

/// The rewritten payload, or None when nothing changes.
pub(super) fn received(v: Version, op: u32, p: &Node, received: i64) -> Option<Node> {
    if v != Version(1, 0) || !OPERATIONS.contains(&op) {
        return None;
    }
    let mut payload = p.clone();
    let mut changed = false;
    let Value::Structure(fields) = &mut payload.value else {
        return None;
    };
    for container in fields.iter_mut().filter(|f| CONTAINERS.contains(&f.tag)) {
        let Value::Structure(attributes) = &mut container.value else {
            continue;
        };
        for attribute in attributes.iter_mut().filter(|a| a.tag == ATTRIBUTE) {
            let Value::Structure(parts) = &mut attribute.value else {
                continue;
            };
            let named = parts.iter().any(|n| {
                n.tag == ATTRIBUTE_NAME && n.string().is_ok_and(|s| s == "Activation Date")
            });
            for value in parts.iter_mut().filter(|n| n.tag == ATTRIBUTE_VALUE) {
                if let Value::DateTime(date) = &mut value.value
                    && named
                    && *date <= received
                {
                    *date = received;
                    changed = true;
                }
            }
        }
    }
    changed.then_some(payload)
}
