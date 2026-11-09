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

//! Operation Policy Name (KMIP 1.0 section 3.13, 1.1-1.4 section 3.18).
//!
//! The server has exactly one named operation policy, `default`
//! (1.0-1.2 3.18.2: "SHALL implement at least one named operation policy
//! [...] This policy is named default"; 1.3/1.4 make it a MAY and deprecate
//! the attribute; 2.0 removes it). Every object reports that name in
//! 1.0-1.4, whether the client supplied it or not ("It is set either
//! explicitly or via some default set by the server"). A client may name
//! `default` when creating or registering an object (also inside a
//! Template) or in a Locate filter; any other name is refused because no such
//! policy exists. The attribute is read-only for clients (Table 73:
//! "Modifiable by client No", "Deletable by client No"). The name is implied,
//! so a request value is validated and dropped rather than stored; 2.x
//! requests on 1.x objects therefore never meet it.
//!
//! The name describes the enforcement that already applies to every object,
//! which is at least as strict as the published `default` tables:
//! - Secret objects (Table 74): every listed operation is allowed to the
//!   creator only. The creator is the authenticated ownership principal (the
//!   client certificate's policy principal), and the principal's operation
//!   ACL can deny the creator further. Operator-configured exact-object read
//!   grants (Locate, Get, Get Attributes, Get Attribute List; see
//!   docs/authorization.md) are an out-of-protocol policy extension that can
//!   admit another principal to one named object.
//! - Certificates and public keys (Table 75): the table allows Locate, Check,
//!   Get, Get Attributes, Get Attribute List and Obtain Lease to all. This
//!   server allows them to the creator only (plus exact-object grants), so
//!   another principal gets Item Not Found. This is stricter than the table
//!   and is not relaxed without an explicit operator grant.
//! - Templates (Tables 76/77) follow the same creator-only rule; there are
//!   no server-published public templates.
use super::*;

/// The only operation policy this server implements.
pub(super) const DEFAULT: &str = "default";

/// The attribute exists in KMIP 1.0-1.4 only.
pub(super) fn defined(v: Version) -> bool {
    v.0 == 1
}
/// A client-supplied Operation Policy Name (Create, Register, templates,
/// Locate filters): a Text String naming a policy the server implements.
pub(super) fn validate(a: &Node) -> R<()> {
    match &a.value {
        Value::TextString(name) if name == DEFAULT => Ok(()),
        Value::TextString(_) => Err(fail(7, "Unknown operation policy")),
        _ => Err(fail(7, "Operation Policy Name must be a Text String")),
    }
}
/// Every non-Template object reports the policy that governs it in 1.0-1.4;
/// later versions have no such attribute.
pub(super) fn project(v: Version, attrs: &mut Vec<Node>) {
    attrs.retain(|a| a.tag != OPERATION_POLICY_NAME);
    if defined(v) {
        attrs.push(Node::text(OPERATION_POLICY_NAME, DEFAULT));
    }
}
/// Request attributes of an operation that creates an object: validate a
/// supplied name, then drop it (the policy is implied for every object).
pub(super) fn strip(attrs: &mut Vec<Node>) -> R<()> {
    let mut supplied = attrs.iter().filter(|a| a.tag == OPERATION_POLICY_NAME);
    if let Some(a) = supplied.next() {
        validate(a)?;
    }
    if supplied.next().is_some() {
        return Err(fail(
            8,
            "Multiple instances of an attribute are not supported",
        ));
    }
    attrs.retain(|a| a.tag != OPERATION_POLICY_NAME);
    Ok(())
}
