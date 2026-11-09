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

//! The TLS connection a request arrived on, and what the store says about a
//! client certificate at a new handshake.
//!
//! `main.rs` maps a handshake's certificate fingerprint to a policy entry
//! (`resolve_principal`), consulting the store first: a fingerprint that a
//! Re-Provision retired is refused, and a replacement fingerprint maps to
//! the entry of the certificate it replaced (provisioning.rs). The engine
//! keeps the connection for the duration of each request (`with_channel`)
//! so that Re-Provision knows which certificate it replaces and tickets know
//! which certificate obtained them. The channel never gates ordinary
//! requests: an open connection keeps the principal it was given at its
//! handshake until it closes. Queued batches run without a channel.
use super::*;

/// One client TLS connection.
#[derive(Clone, Debug)]
pub struct Channel {
    /// SHA-256 of the client certificate (DER), lowercase hex.
    pub fingerprint: String,
    /// The policy-file fingerprint whose entry authorizes this connection:
    /// `fingerprint` itself, or the one a Re-Provision replaced.
    pub policy_fingerprint: String,
    /// The client certificate, DER.
    pub certificate: Vec<u8>,
    /// The rest of the certificate chain the client sent, DER, leaf first
    /// excluded; untrusted intermediates for re-verification.
    pub chain: Vec<Vec<u8>>,
}

/// What the store records about a client certificate fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// No record: the policy file decides.
    Unknown,
    /// A Re-Provision issued or adopted this certificate as the replacement
    /// of the one whose policy entry is `policy_fingerprint`, for the
    /// principal named `principal`.
    Replacement {
        policy_fingerprint: String,
        principal: String,
    },
    /// A Re-Provision replaced this certificate: new connections are refused.
    Retired,
}

impl Engine {
    /// Run `f` with `channel` as the connection of the request in progress.
    pub fn with_channel<T>(&mut self, channel: &Channel, f: impl FnOnce(&mut Self) -> T) -> T {
        let previous = self.channel.replace(channel.clone());
        let result = f(self);
        self.channel = previous;
        result
    }
}

/// Whether a request item names its object through the ID Placeholder: its
/// primary identifier is omitted (KMIP 1.x/2.x, where the placeholder then
/// applies) or is the Unique Identifier enumeration ID Placeholder (1).
fn uses_placeholder(v: Version, item: &Node) -> Option<u32> {
    let op = item.get(OPERATION)?.number().ok()?;
    let payload = item.get(REQUEST_PAYLOAD)?;
    let uses = match payload.get(identifiers::request_identifier_tag(v, op)) {
        None => v.0 < 3,
        Some(n) => matches!(n.value, Value::Enumeration(1)),
    };
    uses.then_some(op)
}

/// For each request item, the operations of the items after it that use
/// the ID Placeholder (`Authorization::later_placeholder_ops`).
pub(super) fn later_placeholder_ops(v: Version, items: &[&Node]) -> Vec<Vec<u32>> {
    let uses: Vec<Option<u32>> = items.iter().map(|item| uses_placeholder(v, item)).collect();
    (0..items.len())
        .map(|index| uses[index + 1..].iter().flatten().copied().collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(op: u32, payload: Vec<Node>) -> Node {
        Node::structure(
            BATCH_ITEM,
            vec![
                Node::enumeration(OPERATION, op),
                Node::structure(REQUEST_PAYLOAD, payload),
            ],
        )
    }

    #[test]
    fn later_placeholder_ops_lists_later_items_that_use_the_placeholder() {
        let v = Version(2, 1);
        let items = [
            item(53, vec![]),
            item(10, vec![]),
            item(11, vec![Node::enumeration(UNIQUE_IDENTIFIER, 1)]),
            item(10, vec![Node::text(UNIQUE_IDENTIFIER, "k")]),
        ];
        let refs: Vec<&Node> = items.iter().collect();
        let later = later_placeholder_ops(v, &refs);
        assert_eq!(later[0], vec![10, 11]);
        assert_eq!(later[1], vec![11]);
        assert!(later[2].is_empty() && later[3].is_empty());
        // Draft 3.0 requires the identifier: only the enumeration counts.
        let later = later_placeholder_ops(Version(3, 0), &refs);
        assert_eq!(later[0], vec![11]);
    }
}
