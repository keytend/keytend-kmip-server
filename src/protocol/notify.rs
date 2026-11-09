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

//! Server-to-client Notify and Put (1.0-1.4 section 5; 2.0/2.1 section 6.2).
//!
//! The specification leaves delivery to "unspecified configuration or
//! administrative mechanisms". Here a principal opts in with an explicitly
//! configured endpoint and protocol version. After a batch commits, every
//! object of that principal written by the batch yields at most one message:
//! Put for a newly stored object (Put Function Replace when it carries a
//! Replaced Object Link, otherwise New) and Notify for changed attributes of
//! an existing object. Messages are handed to a bounded, non-blocking sink;
//! transport, retries and their audit live outside the engine.
//!
//! Put sends key material, so the object value is produced exactly as an
//! unwrapped Get by the owner would produce it: Sensitive, non-extractable or
//! destroyed objects are never pushed, and such skips are audited.
use super::*;
use std::collections::{BTreeMap, HashMap};

pub const NOTIFY: u32 = 27;
pub const PUT: u32 = 28;

/// One principal's opt-in. The version is the protocol version of the
/// server-initiated request messages sent to that principal's endpoint.
#[derive(Clone, Copy)]
pub struct Subscription {
    pub version: Version,
    pub notify: bool,
    pub put: bool,
}
/// A complete server-initiated request message for one object.
pub struct Outbound {
    /// The subscribed certificate principal whose endpoint receives it.
    pub endpoint: String,
    /// The object's owner: the principal, or one of its credential
    /// identities (see `system::certificate_principal`).
    pub owner: String,
    pub operation: u32,
    pub object: String,
    pub message: Node,
}
/// Returns false when the message cannot be queued; it must never block.
pub type Sink = Box<dyn Fn(Outbound) -> bool + Send>;
pub struct ServerToClient {
    subscriptions: HashMap<String, Subscription>,
    sink: Sink,
}
impl ServerToClient {
    /// Delivery versions are the final editions 1.0 through 2.1.
    pub fn new(
        subscriptions: HashMap<String, Subscription>,
        sink: Sink,
    ) -> Result<Self, &'static str> {
        for s in subscriptions.values() {
            if !Version::supported(false).contains(&s.version) {
                return Err("server-to-client delivery requires protocol 1.0 through 2.1");
            }
            if !s.notify && !s.put {
                return Err("a server-to-client subscription needs Notify or Put");
            }
        }
        Ok(Self {
            subscriptions,
            sink,
        })
    }
}
fn message(v: Version, operation: u32, payload: Vec<Node>) -> Node {
    // 1.0 5.1/5.2: the request format without Maximum Response Size,
    // Asynchronous Indicator, Batch Error Continuation or Batch Order Option.
    Node::structure(
        REQUEST_MESSAGE,
        vec![
            Node::structure(REQUEST_HEADER, vec![v.node(), Node::int(BATCH_COUNT, 1)]),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, operation),
                    Node::structure(REQUEST_PAYLOAD, payload),
                ],
            ),
        ],
    )
}
type Instances = BTreeMap<String, Vec<(i32, Node)>>;
fn instances(obj: &Object, v: Version) -> R<Instances> {
    let attrs = object_attrs(obj, v);
    let mut totals = HashMap::<String, usize>::new();
    for a in &attrs {
        *totals.entry(attributes::identity(a)?).or_default() += 1;
    }
    let mut out = Instances::new();
    for a in attrs {
        let key = attributes::identity(&a)?;
        let list = out.entry(key.clone()).or_default();
        let index = attributes::indices(obj, &key, totals[&key])?[list.len()];
        list.push((index, a));
    }
    Ok(out)
}
fn reference(a: &Node) -> R<Node> {
    if a.tag == ATTRIBUTE {
        let (vendor, name) = vendor_identity(a)?;
        return Ok(Node::structure(
            ATTRIBUTE_REFERENCE,
            vec![
                Node::text(VENDOR_IDENTIFICATION, vendor),
                Node::text(ATTRIBUTE_NAME, name),
            ],
        ));
    }
    Ok(Node::enumeration(ATTRIBUTE_REFERENCE, a.tag))
}
/// Notify payload: changed attributes, including at least Last Change Date,
/// and deleted ones. 1.x (table 167) lists Attribute structures and marks a
/// deleted instance by omitting its Attribute Value; 2.x (2.1 6.2.2) sends an
/// Attributes structure and one Attribute Reference per deleted attribute.
/// In 2.x a partly deleted multi-instance attribute is sent with all of its
/// remaining instances. Returns None when nothing but Last Change Date moved.
fn notify_payload(before: &Object, after: &Object, v: Version) -> R<Option<Vec<Node>>> {
    let old = instances(before, v)?;
    let new = instances(after, v)?;
    let last_change = attributes::identity(&Node::date(LAST_CHANGE_DATE, 0))?;
    let multi_signature = after.object_type != 1 || after.certificate_type == 2;
    let mut changed = vec![];
    let mut deleted = vec![];
    let mut meaningful = false;
    let mut last_change_sent = false;
    let keys = old
        .keys()
        .chain(new.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for key in keys {
        let empty = vec![];
        let was = old.get(&key).unwrap_or(&empty);
        let now = new.get(&key).unwrap_or(&empty);
        if was == now {
            continue;
        }
        if key == last_change {
            last_change_sent = true;
        } else {
            meaningful = true;
        }
        if v.0 == 1 {
            for (index, a) in now {
                if !was.contains(&(*index, a.clone())) {
                    changed.push(attributes::encode_attribute_at(a, *index, multi_signature)?);
                }
            }
            for (index, a) in was {
                if !now.iter().any(|(i, _)| i == index) {
                    let mut gone = attributes::encode_attribute_at(a, *index, multi_signature)?;
                    if let Value::Structure(fields) = &mut gone.value {
                        fields.retain(|f| f.tag != ATTRIBUTE_VALUE);
                    }
                    deleted.push(gone);
                }
            }
        } else if now.is_empty() {
            deleted.push(reference(&was[0].1)?);
        } else {
            changed.extend(now.iter().map(|(_, a)| a.clone()));
        }
    }
    if !meaningful {
        return Ok(None);
    }
    if !last_change_sent {
        let a = Node::date(LAST_CHANGE_DATE, after.updated);
        changed.push(if v.0 == 1 { encode_attribute(&a)? } else { a });
    }
    let mut payload = vec![Node::text(UNIQUE_IDENTIFIER, &after.id)];
    if v.0 == 1 {
        payload.extend(changed);
        payload.extend(deleted);
    } else {
        payload.push(Node::structure(ATTRIBUTES, changed));
        payload.extend(deleted);
    }
    Ok(Some(payload))
}
impl Engine {
    pub fn with_server_to_client(mut self, delivery: ServerToClient) -> Self {
        self.server_to_client = Some(delivery);
        self
    }
    /// The subscription of the certificate principal behind `owner`, so the
    /// objects of its credential identities use the principal's endpoint.
    pub(super) fn subscription(&self, owner: &str) -> Option<Subscription> {
        let principal = system::certificate_principal(owner)?;
        self.server_to_client
            .as_ref()
            .and_then(|s| s.subscriptions.get(principal).copied())
    }
    /// Query Operations: Notify and Put are listed only for a principal whose
    /// delivery is configured, since only then does this server perform them;
    /// Interop only in interop test mode.
    pub(super) fn advertised_operations(&self, owner: &str, v: Version) -> Vec<u32> {
        let mut ops = self.offered_operations(v);
        if let Some(s) = self.subscription(owner) {
            if s.notify {
                ops.push(NOTIFY);
            }
            if s.put {
                ops.push(PUT);
            }
            ops.sort();
        }
        ops
    }
    pub(super) fn record_server_changes(&self) {
        if self
            .server_to_client
            .as_ref()
            .is_some_and(|s| !s.subscriptions.is_empty())
        {
            self.store.record_changes();
        }
    }
    fn skipped(&self, owner: &str, operation: u32, id: &str, why: &str) {
        tracing::warn!(%owner, operation, object=%id, reason=%why, "server-to-client message not sent");
        if let Err(error) = self.store.audit(owner, operation, Some(id), 1) {
            tracing::error!(%error, "server-to-client audit failed");
        }
    }
    /// Build messages for the recorded writes, inside the batch transaction.
    /// Never fails the client's batch: problems are logged and audited.
    pub(super) fn server_messages(&self) -> Vec<Outbound> {
        let changes = self.store.take_changes();
        let mut out = vec![];
        for change in changes {
            let Some(s) = self.subscription(&change.owner) else {
                continue;
            };
            let Ok(Some(mut after)) = self.store.get(&change.owner, &change.id) else {
                continue;
            };
            if metadata::hydrate(&mut after).is_err() {
                continue;
            }
            // A 1.x subscriber has no Certificate Request object type.
            if !certificate_request::visible(&after, Some(s.version)) {
                continue;
            }
            let built = match &change.before {
                None if s.put => self.put_payload(&after, s.version).map(|p| Some((PUT, p))),
                Some(before) if s.notify => {
                    let mut before = before.clone();
                    match metadata::hydrate(&mut before) {
                        Ok(()) => notify_payload(&before, &after, s.version)
                            .map(|p| p.map(|p| (NOTIFY, p))),
                        Err(e) => Err(e),
                    }
                }
                _ => continue,
            };
            let operation = if change.before.is_none() { PUT } else { NOTIFY };
            match built {
                Ok(Some((operation, payload))) => {
                    let message = message(s.version, operation, payload);
                    if message.encoded_len() > crate::ttlv::MAX_FRAME {
                        self.skipped(&change.owner, operation, &change.id, "message too large");
                        continue;
                    }
                    out.push(Outbound {
                        endpoint: system::certificate_principal(&change.owner)
                            .unwrap_or_default()
                            .to_owned(),
                        owner: change.owner,
                        operation,
                        object: change.id,
                        message,
                    });
                }
                Ok(None) => {}
                Err(e) => self.skipped(&change.owner, operation, &change.id, e.message),
            }
        }
        out
    }
    /// Put payload (1.0 table 168; 2.1 6.2.3). The object is exactly what an
    /// unwrapped Get by the owner returns, so Get's sensitivity,
    /// extractability, state and format rules apply unchanged.
    fn put_payload(&self, obj: &Object, v: Version) -> R<Vec<Node>> {
        let request = Node::structure(
            REQUEST_PAYLOAD,
            vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)],
        );
        let object = self
            .get(&obj.owner, v, &request, &None, false)?
            .into_iter()
            .nth(2)
            .ok_or(fail(0x100, "Get returned no object"))?;
        let attributes = self.get_attrs(&obj.owner, v, &request, &None, false)?;
        let replaced = obj
            .attrs
            .iter()
            .find(|a| link_kind(a) == Some(0x107))
            .and_then(|a| a.get(LINKED_OBJECT_IDENTIFIER))
            .and_then(|n| n.identifier_text().ok());
        let mut payload = vec![
            Node::text(UNIQUE_IDENTIFIER, &obj.id),
            Node::enumeration(PUT_FUNCTION, if replaced.is_some() { 2 } else { 1 }),
        ];
        if let Some(replaced) = replaced {
            payload.push(Node::text(REPLACED_UNIQUE_IDENTIFIER, replaced));
        }
        payload.push(object);
        payload.extend(
            attributes
                .into_iter()
                .filter(|n| n.tag != UNIQUE_IDENTIFIER),
        );
        Ok(payload)
    }
    /// Hand committed messages to the sink; a full queue is audited, not waited on.
    pub(super) fn deliver(&self, messages: Vec<Outbound>) {
        let Some(s) = &self.server_to_client else {
            return;
        };
        for m in messages {
            let (owner, operation, id) = (m.owner.clone(), m.operation, m.object.clone());
            if !(s.sink)(m) {
                self.skipped(&owner, operation, &id, "delivery queue is full");
            }
        }
    }
}
