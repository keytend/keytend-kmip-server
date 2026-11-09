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

//! Client-to-server Set Endpoint Role (2.0 section 6.1.48, 2.1 section
//! 6.1.54, draft 3.0 section 6.1.61).
//!
//! "After successful completion of the operation the server assumes the
//! client role, and the client assumes the server role, but the
//! communication channel remains as established." The engine only decides
//! whether the requested role is accepted; the connection that carried the
//! request performs the reversal after the response is written (see
//! `delivery::Reverse`), using the reversed channel to send this principal's
//! server-to-client messages.
//!
//! - Endpoint Role Server: the server already has that role; it is accepted
//!   and nothing changes.
//! - Endpoint Role Client: accepted only on a binary TTLV connection (an HTTP
//!   exchange cannot be reversed), for a principal that has a configured
//!   server-to-client subscription (a `client_endpoint`), and only in that
//!   subscription's protocol version, so every message on the reversed
//!   channel uses one version. Draft 3.0 has no server-to-client delivery
//!   here, so the Client role is refused there.
use super::*;

pub const SET_ENDPOINT_ROLE: u32 = 0x32;
/// Endpoint Role enumeration (2.1 section 11.19, table 452).
pub const ROLE_CLIENT: u32 = 1;
pub const ROLE_SERVER: u32 = 2;

/// Whether `response` carries a successful Set Endpoint Role that made the
/// server the client. A batch that failed, was undone or deferred never does.
pub fn reversal_accepted(response: &Node) -> bool {
    let mut reversed = false;
    for item in response.all(BATCH_ITEM) {
        if item.get(OPERATION).and_then(|n| n.number().ok()) != Some(SET_ENDPOINT_ROLE)
            || item.get(RESULT_STATUS).and_then(|n| n.number().ok()) != Some(0)
        {
            continue;
        }
        // The last accepted role applies to subsequent messages.
        reversed = item
            .get(RESPONSE_PAYLOAD)
            .and_then(|p| p.get(ENDPOINT_ROLE))
            .and_then(|n| n.number().ok())
            == Some(ROLE_CLIENT);
    }
    reversed
}

impl Engine {
    /// Process a request received on a channel that can be reversed (one
    /// binary TTLV connection). Identical to `process_with_grants` except that
    /// Set Endpoint Role may accept the Client role.
    pub fn process_reversible(
        &mut self,
        owner: &str,
        request: &Node,
        allowed: Option<&[u32]>,
        grants: &[crate::authorization::ObjectGrant],
    ) -> R<Node> {
        self.reversible_channel = true;
        let result = self.process_with_grants(owner, request, allowed, grants);
        self.reversible_channel = false;
        result
    }
    /// Tables 331/332 (2.1): one REQUIRED Endpoint Role in, the accepted
    /// role out.
    pub(super) fn set_endpoint_role(&self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        no_fields(p, &[ENDPOINT_ROLE])?;
        let role = p.required(ENDPOINT_ROLE)?;
        let Value::Enumeration(role) = role.value else {
            return Err(fail(7, "Endpoint Role must be an enumeration"));
        };
        match role {
            ROLE_SERVER => {}
            ROLE_CLIENT => {
                let Some(subscription) = self.subscription(owner) else {
                    return Err(fail(
                        12,
                        "Server policy configures no client endpoint for this principal",
                    ));
                };
                if !self.reversible_channel {
                    return Err(fail(8, "This channel cannot be reversed"));
                }
                if subscription.version != v {
                    return Err(fail(
                        8,
                        "Role reversal requires the client endpoint protocol version",
                    ));
                }
            }
            _ => return Err(fail(7, "Invalid Endpoint Role")),
        }
        Ok(vec![Node::enumeration(ENDPOINT_ROLE, role)])
    }
}
