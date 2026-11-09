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

//! Login tickets (KMIP 2.0/2.1 sections 6.1.29/6.1.30 and 6.1.30/6.1.31,
//! draft 3.0 6.1.36/6.1.37) and Delegated Login (2.0/2.1 section 6.1.12).
//!
//! Mutual TLS has already selected the certificate principal. A Login ticket
//! stands for that principal plus whatever the Login request's header
//! credentials proved (a user and/or device, or nothing in 2.x; draft 3.0
//! keeps its rule that the user proves a password). It is redeemed only by
//! the same principal and in requests of the same major edition. A
//! delegated ticket is a bearer ticket: any listed certificate presenting it
//! acts as the delegator, but every item needs the presenter's own
//! allowlist, the delegator's allowlist at issue, a permitting Right and
//! budget (`ticket_authorize_item`).
//!
//! Tickets live in memory as SHA-256 digests of their random values, at most
//! 64 per issuing principal, and are lost on restart. Request Count is
//! charged once per message when the ticket is redeemed. Usage Limits (Unit
//! Object: one batch item) are shared `Arc<AtomicU64>` counters, so the
//! batch loop's ticket snapshots never refund them: Undo cannot replay key
//! material. Every ticket records the client certificate fingerprint that
//! obtained it, so that a Re-Provision of that certificate revokes it.
//! docs/tickets.md lists the interpretations.
use super::system::{Identity, auth_failed, principal_of};
use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Result Reason Invalid Ticket (2.0/2.1 table "Result Reason", draft 3.0
/// table 595).
const INVALID_TICKET: u32 = 0x19;
/// Ticket Type Login, the only value (2.1 section 11.57, draft 3.0 table 606).
const LOGIN_TICKET: u32 = 1;
const TICKET_BYTES: usize = 32;
const DEFAULT_TICKET_SECONDS: i64 = 3600;
const MAX_TICKET_SECONDS: i64 = 86_400;
const MAX_TICKETS_PER_OWNER: usize = 64;
const MAX_RIGHTS: usize = 16;
const MAX_RIGHT_OPERATIONS: usize = 66;
const MAX_RIGHT_OBJECTS: usize = 32;
/// Usage Limits Unit (2.1 section 11.60).
const UNIT_BYTE: u32 = 1;
const UNIT_OBJECT: u32 = 2;
const LOGOUT: u32 = 46;
/// Operations a delegated ticket never performs: asynchronous control
/// (Cancel, Poll, Query Asynchronous Requests, Process), ticket issuance,
/// Set Endpoint Role, Re-Provision, the server-wide settings and the draft
/// 3.0 System Object operations.
const NEVER_DELEGATED: [u32; 15] = [25, 26, 45, 47, 50, 52, 53, 54, 55, 57, 58, 60, 61, 62, 63];
/// Operations whose sole object reference is the item's primary identifier,
/// the only ones a Right with Objects can permit.
const OBJECT_SCOPED: [u32; 26] = [
    9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 31, 32, 33, 34, 35, 36, 43, 48, 49, 64,
    65, 66,
];
/// Fields that name a managed object.
const REFERENCES: [u32; 6] = [
    UNIQUE_IDENTIFIER,
    PRIVATE_KEY_UNIQUE_IDENTIFIER,
    PUBLIC_KEY_UNIQUE_IDENTIFIER,
    LINKED_OBJECT_IDENTIFIER,
    REPLACED_UNIQUE_IDENTIFIER,
    CERTIFICATE_REQUEST_UNIQUE_IDENTIFIER,
];

/// One live ticket.
#[derive(Clone)]
pub(super) struct Ticket {
    /// The issuing certificate principal (policy name).
    owner: String,
    /// Major protocol version of the issuing request.
    edition: u32,
    /// Fingerprint of the client certificate that obtained the ticket (None
    /// for in-process requests).
    issued_by: Option<String>,
    /// The identity the Login request proved (for a delegated ticket, the
    /// delegator's).
    user: Option<String>,
    device: Option<String>,
    /// The System credential that proved the user (None: users file).
    credential: Option<String>,
    expires: i64,
    /// Request Count remaining: new messages that may present the ticket.
    requests: Option<u32>,
    /// Usage Limits remaining, shared by every clone and never refunded.
    usage: Option<Arc<AtomicU64>>,
    delegation: Option<Arc<Delegation>>,
}
impl Ticket {
    pub(super) fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }
    pub(super) fn device(&self) -> Option<&str> {
        self.device.as_deref()
    }
    pub(super) fn credential(&self) -> Option<&str> {
        self.credential.as_deref()
    }
    pub(super) fn delegation(&self) -> Option<Arc<Delegation>> {
        self.delegation.clone()
    }
}

/// The immutable context of a delegated ticket, copied into the request's
/// `Identity` when it is redeemed.
pub(super) struct Delegation {
    /// The managed-object owner the delegate acts as.
    pub(super) delegator_owner: String,
    /// The delegator's audit principal at issue.
    pub(super) delegator_audit: String,
    /// The delegator's allowlist at issue, minus `NEVER_DELEGATED`.
    operations: Vec<u32>,
    rights: Vec<Right>,
}

/// One Right (2.1 section 7.34): an omitted field is unrestricted.
struct Right {
    operations: Option<Vec<u32>>,
    objects: Option<Vec<String>>,
    usage: Option<Arc<AtomicU64>>,
}
impl Right {
    fn permits(&self, op: u32, target: Option<&str>, payload: Option<&Node>) -> bool {
        if self
            .operations
            .as_ref()
            .is_some_and(|ops| !ops.contains(&op))
        {
            return false;
        }
        let Some(objects) = &self.objects else {
            return true;
        };
        let Some(target) = target else {
            return false;
        };
        // The target must be the only object the item names: the primary
        // identifier, or nothing when it is the ID Placeholder.
        let named = payload.map_or(0, references);
        let primary = payload.is_some_and(|p| p.get(UNIQUE_IDENTIFIER).is_some());
        OBJECT_SCOPED.contains(&op)
            && named == usize::from(primary)
            && objects.iter().any(|o| o == target)
    }
}
/// How many object references a payload contains.
fn references(n: &Node) -> usize {
    match &n.value {
        Value::Structure(fields) => fields.iter().map(references).sum(),
        Value::Identifier(_) | Value::Reference(_) | Value::NameReference(_) => 1,
        _ => usize::from(REFERENCES.contains(&n.tag)),
    }
}
/// Take one unit from a budget; false when it is spent.
fn charge(budget: &AtomicU64) -> bool {
    let mut current = budget.load(Ordering::SeqCst);
    while current > 0 {
        match budget.compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
    false
}

/// Live tickets by SHA-256 digest of their values; a restart forgets them.
#[derive(Clone, Default)]
pub(super) struct Tickets(HashMap<[u8; 32], Ticket>);
impl Tickets {
    /// Remove expired tickets. An exhausted Request Count does not remove a
    /// ticket: messages it authenticated, including queued batches, keep
    /// running until it expires or is logged out.
    fn purge(&mut self) {
        let time = now();
        self.0.retain(|_, t| t.expires > time);
    }
    /// Whether the ticket with this digest exists and has not expired.
    pub(super) fn live(&self, digest: &[u8; 32]) -> bool {
        self.0.get(digest).is_some_and(|t| t.expires > now())
    }
    /// Revoke the tickets a user of `principal` holds (Obliterate of a User).
    pub(super) fn revoke_user(&mut self, principal: &str, user: &str) {
        self.0
            .retain(|_, t| t.owner != principal || t.user.as_deref() != Some(user));
    }
    /// Revoke the tickets a System credential proved (Obliterate).
    pub(super) fn revoke_credential(&mut self, principal: &str, credential: &str) {
        self.0
            .retain(|_, t| t.owner != principal || t.credential.as_deref() != Some(credential));
    }
}

impl Tickets {
    /// Revoke every ticket obtained over the client certificate with this
    /// fingerprint (called when a Re-Provision retires it).
    pub(super) fn revoke_fingerprint(&mut self, fingerprint: &str) {
        self.0
            .retain(|_, t| t.issued_by.as_deref() != Some(fingerprint));
    }
}

fn ticket_digest(n: &Node) -> Option<[u8; 32]> {
    no_fields(n, &[TICKET_TYPE, TICKET_VALUE]).ok()?;
    if n.get(TICKET_TYPE)?.number().ok()? != LOGIN_TICKET {
        return None;
    }
    let value = n.get(TICKET_VALUE)?.byte_string().ok()?;
    (value.len() == TICKET_BYTES).then(|| crypto::sha256(value))
}
/// The ticket's expiry from Lease Time: an Interval of 1 to 86,400 seconds,
/// or a Date Time at most 24 hours ahead; one hour by default.
fn expiry(p: &Node, time: i64) -> R<i64> {
    let seconds = match p.get(LEASE_TIME).map(|n| &n.value) {
        None => DEFAULT_TICKET_SECONDS,
        Some(Value::Interval(seconds)) => i64::from(*seconds),
        Some(Value::DateTime(until)) => until.saturating_sub(time),
        Some(_) => return Err(fail(7, "Invalid Lease Time")),
    };
    if !(1..=MAX_TICKET_SECONDS).contains(&seconds) {
        return Err(fail(7, "Lease Time is outside the server range"));
    }
    Ok(time + seconds)
}
/// Usage Limits (2.1 section 7.40): Total, Count and Unit are required;
/// only Unit Object (one batch item) is supported, with 1 <= Count <= Total.
fn budget(n: &Node) -> R<Arc<AtomicU64>> {
    no_fields(
        n,
        &[USAGE_LIMITS_TOTAL, USAGE_LIMITS_COUNT, USAGE_LIMITS_UNIT],
    )?;
    let total = usage::nonnegative_long(n.required(USAGE_LIMITS_TOTAL)?)?;
    let count = usage::nonnegative_long(n.required(USAGE_LIMITS_COUNT)?)?;
    match n.required(USAGE_LIMITS_UNIT)?.value {
        Value::Enumeration(UNIT_OBJECT) => {}
        Value::Enumeration(UNIT_BYTE) => {
            return Err(fail(8, "Usage Limits Unit Byte is not supported"));
        }
        _ => return Err(fail(7, "Invalid Usage Limits Unit")),
    }
    if count < 1 || count > total {
        return Err(fail(7, "Usage Limits Count must be between 1 and Total"));
    }
    Ok(Arc::new(AtomicU64::new(count as u64)))
}
/// The object an item acts on, after `prepare_identifiers`: its primary
/// identifier, or in 1.x/2.x the ID Placeholder when that is omitted. A
/// multi-part continuation that carries a Correlation Value has none.
fn item_target(v: Version, op: u32, item: &Node, placeholder: &Option<String>) -> Option<String> {
    let p = item.get(REQUEST_PAYLOAD)?;
    if p.get(CORRELATION_VALUE).is_some() {
        return None;
    }
    match p.get(identifiers::request_identifier_tag(v, op)) {
        Some(n) => n.identifier_text().ok().map(str::to_owned),
        None if v.0 < 3 => placeholder.clone(),
        None => None,
    }
}
fn denied(message: &'static str) -> Failure {
    fail(12, message)
}

impl Engine {
    /// Login (2.0/2.1 section 6.1.29/6.1.30, draft 3.0 6.1.36). In 2.x the
    /// ticket stands for whatever the request proved, possibly the
    /// certificate principal alone; draft 3.0 requires a user who proves a
    /// password in the same request.
    pub(super) fn login(&mut self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        no_fields(p, &[LEASE_TIME, REQUEST_COUNT, USAGE_LIMITS])?;
        self.refuse_issuance()?;
        if v.0 >= 3
            && self
                .authorization
                .identity
                .as_ref()
                .is_none_or(|i| i.user.is_none())
        {
            return Err(denied("Login requires a password credential"));
        }
        self.issue(owner, v, p, None)
    }
    /// Delegated Login (2.0/2.1 section 6.1.12, draft 3.0 6.1.17): a bearer
    /// ticket that acts as this request's owner, limited to its Rights.
    pub(super) fn delegated_login(
        &mut self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(p, &[LEASE_TIME, REQUEST_COUNT, USAGE_LIMITS, RIGHTS])?;
        self.refuse_issuance()?;
        let list = p.required(RIGHTS)?.children()?;
        if list.is_empty() || list.iter().any(|n| n.tag != RIGHT) {
            return Err(fail(7, "Rights must contain at least one Right"));
        }
        if list.len() > MAX_RIGHTS {
            return Err(server_limit(v, "Too many Rights"));
        }
        // The delegator's allowlist at issue: never more than it may do.
        let allowed = self.authorization.allowed.clone();
        let operations = self
            .offered_operations(v)
            .into_iter()
            .filter(|op| {
                !NEVER_DELEGATED.contains(op) && allowed.as_ref().is_none_or(|a| a.contains(op))
            })
            .collect::<Vec<_>>();
        let rights = list
            .iter()
            .map(|r| self.read_right(owner, v, r, allowed.as_deref(), placeholder))
            .collect::<R<Vec<_>>>()?;
        let principal = principal_of(owner);
        let delegator_audit = match &self.authorization.identity {
            Some(identity) => identity.audit_principal(principal),
            None => principal.to_owned(),
        };
        let delegation = Delegation {
            delegator_owner: owner.to_owned(),
            delegator_audit,
            operations,
            rights,
        };
        self.issue(owner, v, p, Some(delegation))
    }
    /// Logout (2.0/2.1 section 6.1.30/6.1.31, draft 3.0 6.1.37): the issuing
    /// principal, or a request that presents the ticket, ends it at once.
    /// An unknown, expired or foreign ticket is Invalid Ticket.
    pub(super) fn logout(&mut self, owner: &str, _v: Version, p: &Node) -> R<Vec<Node>> {
        no_fields(p, &[TICKET])?;
        let principal = principal_of(owner);
        let presented = self.authorization.identity.as_ref().and_then(|i| i.ticket);
        self.tickets.purge();
        let digest = ticket_digest(p.required(TICKET)?)
            .filter(|d| {
                self.tickets
                    .0
                    .get(d)
                    .is_some_and(|t| t.owner == principal || presented == Some(*d))
            })
            .ok_or(fail(INVALID_TICKET, "Invalid Ticket"))?;
        self.tickets.0.remove(&digest);
        Ok(vec![])
    }
    /// Redeem a Ticket credential: a Login ticket of this principal, or any
    /// delegated ticket presented alone, issued in the same major edition
    /// and with Request Count left, whose holder still exists. Request Count
    /// is charged here, before the message's ticket snapshot, so it is never
    /// refunded.
    pub(super) fn redeem_ticket(
        &mut self,
        owner: &str,
        v: Version,
        value: &Node,
        alone: bool,
    ) -> R<([u8; 32], Ticket)> {
        no_fields(value, &[TICKET])?;
        self.tickets.purge();
        let digest = ticket_digest(value.required(TICKET)?).ok_or_else(auth_failed)?;
        let ticket = self
            .tickets
            .0
            .get(&digest)
            .filter(|t| t.edition == v.0 && (t.delegation.is_some() || t.owner == owner))
            .filter(|t| alone || t.delegation.is_none())
            .filter(|t| t.requests != Some(0))
            .cloned()
            .ok_or_else(auth_failed)?;
        // The user, device or credential may have been removed since issue.
        let holder = Identity {
            user: ticket.user.clone(),
            device: ticket.device.clone(),
            credential: ticket.credential.clone(),
            ..Identity::default()
        };
        if !self.identity_current(&ticket.owner, &holder)? {
            self.tickets.0.remove(&digest);
            return Err(auth_failed());
        }
        if let Some(t) = self.tickets.0.get_mut(&digest)
            && let Some(requests) = t.requests.as_mut()
        {
            *requests -= 1;
        }
        Ok((digest, ticket))
    }
    /// Per-item ticket checks, run inside the item snapshot before the item
    /// executes: the presenting ticket must still be live, its Usage Limits
    /// are charged, and a delegated ticket needs a Right that permits the
    /// item (whose budget is charged). Nothing charged is ever refunded. A
    /// request without a ticket is unaffected.
    pub(super) fn ticket_authorize_item(
        &mut self,
        _owner: &str,
        v: Version,
        op: u32,
        item: &Node,
        placeholder: &Option<String>,
    ) -> R<()> {
        let Some(identity) = self.authorization.identity.as_ref() else {
            return Ok(());
        };
        let Some(digest) = identity.ticket else {
            return Ok(());
        };
        let delegation = identity.delegation.clone();
        let ticket = self
            .tickets
            .0
            .get(&digest)
            .filter(|t| t.expires > now())
            .ok_or(denied(
                "The ticket that authenticated this request has ended",
            ))?;
        if let Some(usage) = &ticket.usage
            && !charge(usage)
        {
            return Err(denied("The ticket's Usage Limits are exhausted"));
        }
        let Some(delegation) = delegation else {
            return Ok(());
        };
        if NEVER_DELEGATED.contains(&op) {
            return Err(denied("This operation cannot be delegated"));
        }
        let payload = item.get(REQUEST_PAYLOAD);
        // A delegate may give up its own ticket, and only that one.
        if op == LOGOUT {
            return if payload.and_then(|p| p.get(TICKET)).and_then(ticket_digest) == Some(digest) {
                Ok(())
            } else {
                Err(denied("A delegated ticket may log out only itself"))
            };
        }
        if !delegation.operations.contains(&op) {
            return Err(denied("The delegator may not perform this operation"));
        }
        let target = item_target(v, op, item, placeholder);
        let permitted = delegation.rights.iter().any(|right| {
            right.permits(op, target.as_deref(), payload)
                && right.usage.as_ref().is_none_or(|u| charge(u))
        });
        if permitted {
            Ok(())
        } else {
            Err(denied("No Right of the delegated ticket permits this item"))
        }
    }
    /// Login and Delegated Login refuse to mint tickets on a connection whose
    /// certificate a Re-Provision retired, and under a ticket (no renewal).
    fn refuse_issuance(&self) -> R<()> {
        if self.channel_retired()? {
            return Err(denied("This client certificate has been re-provisioned"));
        }
        if self
            .authorization
            .identity
            .as_ref()
            .is_some_and(|i| i.ticket.is_some())
        {
            return Err(denied("A ticket cannot obtain another ticket"));
        }
        Ok(())
    }
    fn issue(
        &mut self,
        owner: &str,
        v: Version,
        p: &Node,
        delegation: Option<Delegation>,
    ) -> R<Vec<Node>> {
        let time = now();
        let expires = expiry(p, time)?;
        let requests = p
            .get(REQUEST_COUNT)
            .map(|n| {
                n.number()
                    .ok()
                    .filter(|count| *count > 0)
                    .ok_or(fail(7, "Request Count must be positive"))
            })
            .transpose()?;
        let usage = p.get(USAGE_LIMITS).map(budget).transpose()?;
        // Tickets belong to the certificate principal, whichever identity
        // owns managed objects.
        let principal = principal_of(owner).to_owned();
        self.tickets.purge();
        if self
            .tickets
            .0
            .values()
            .filter(|t| t.owner == principal)
            .count()
            >= MAX_TICKETS_PER_OWNER
        {
            return Err(server_limit(v, "Too many active tickets"));
        }
        let value = crypto::random(TICKET_BYTES).map_err(|_| fail(0x2a, "Random failure"))?;
        let identity = self.authorization.identity.clone().unwrap_or_default();
        let kind = if delegation.is_some() {
            "delegated"
        } else {
            "login"
        };
        self.tickets.0.insert(
            crypto::sha256(&value),
            Ticket {
                owner: principal,
                edition: v.0,
                issued_by: self.channel.as_ref().map(|c| c.fingerprint.clone()),
                user: identity.user,
                device: identity.device,
                credential: identity.credential,
                expires,
                requests,
                usage,
                delegation: delegation.map(Arc::new),
            },
        );
        tracing::info!(kind, expires, "ticket issued");
        Ok(vec![Node::structure(
            TICKET,
            vec![
                Node::enumeration(TICKET_TYPE, LOGIN_TICKET),
                Node::bytes(TICKET_VALUE, value.to_vec()),
            ],
        )])
    }
    /// One Right of a Delegated Login, checked against the delegator.
    fn read_right(
        &self,
        owner: &str,
        v: Version,
        right: &Node,
        allowed: Option<&[u32]>,
        placeholder: &Option<String>,
    ) -> R<Right> {
        // Object Groups (2.1 and draft 3.0) is not supported; 2.0 does not
        // define it.
        if right.get(OBJECT_GROUPS).is_some() {
            return Err(if v >= Version(2, 1) {
                fail(8, "Right Object Groups is not supported")
            } else {
                fail(7, "Object Groups is not a 2.0 Right field")
            });
        }
        no_fields(right, &[USAGE_LIMITS, OPERATIONS, OBJECTS])?;
        let offered = self.offered_operations(v);
        let operations = right
            .get(OPERATIONS)
            .map(|n| {
                let list = n.children()?;
                if list.is_empty() || list.iter().any(|n| n.tag != OPERATION) {
                    return Err(fail(7, "Operations must list at least one Operation"));
                }
                if list.len() > MAX_RIGHT_OPERATIONS {
                    return Err(server_limit(v, "Too many Operations in a Right"));
                }
                let mut ops = vec![];
                for n in list {
                    let Value::Enumeration(op) = n.value else {
                        return Err(fail(7, "Operation must be an Enumeration"));
                    };
                    if NEVER_DELEGATED.contains(&op) {
                        return Err(denied("This operation cannot be delegated"));
                    }
                    if allowed.is_some_and(|a| !a.contains(&op)) {
                        return Err(denied("The delegator may not perform this operation"));
                    }
                    if !offered.contains(&op) {
                        return Err(fail(7, "Operation is not defined in this version"));
                    }
                    ops.push(op);
                }
                Ok(ops)
            })
            .transpose()?;
        let objects = right
            .get(OBJECTS)
            .map(|n| {
                let list = n.children()?;
                if list.is_empty() || list.iter().any(|n| n.tag != UNIQUE_IDENTIFIER) {
                    return Err(fail(7, "Objects must list at least one Unique Identifier"));
                }
                if list.len() > MAX_RIGHT_OBJECTS {
                    return Err(server_limit(v, "Too many Objects in a Right"));
                }
                let mut ids = vec![];
                for n in list {
                    for id in self.right_object(owner, v, n, placeholder)? {
                        // Unknown and foreign identifiers get the same answer.
                        if self.store.get(owner, &id)?.is_none() {
                            return Err(denied("The delegator does not own this object"));
                        }
                        ids.push(id);
                    }
                }
                Ok(ids)
            })
            .transpose()?;
        // A Right with Objects permits only object-scoped operations; any
        // other operation it lists could never be used.
        if objects.is_some()
            && operations
                .as_ref()
                .is_some_and(|ops| ops.iter().any(|op| !OBJECT_SCOPED.contains(op)))
        {
            return Err(fail(
                7,
                "A Right with Objects may list only operations on one object",
            ));
        }
        let usage = right.get(USAGE_LIMITS).map(budget).transpose()?;
        Ok(Right {
            operations,
            objects,
            usage,
        })
    }
    /// The identifiers one Objects entry names: a Text String literally, the
    /// ID Placeholder enumeration as resolved now, and draft 3.0 identifier
    /// types as in any other request.
    fn right_object(
        &self,
        owner: &str,
        v: Version,
        n: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<String>> {
        match &n.value {
            Value::TextString(id) if v.0 < 3 && !id.is_empty() => Ok(vec![id.clone()]),
            Value::Identifier(id) | Value::Reference(id) if v.0 >= 3 && !id.is_empty() => {
                Ok(vec![id.clone()])
            }
            Value::NameReference(_) if v.0 >= 3 => self
                .resolve_identifier(
                    owner,
                    v,
                    n,
                    &identifiers::References::default(),
                    placeholder,
                )
                .map_err(|_| denied("The delegator does not own this object")),
            Value::Enumeration(1) => Ok(vec![
                placeholder
                    .clone()
                    .ok_or(fail(7, "ID Placeholder is empty"))?,
            ]),
            Value::Enumeration(_) | Value::Integer(_) => Err(fail(
                8,
                "Only identifiers and the ID Placeholder are supported in Objects",
            )),
            _ => Err(fail(7, "Invalid Unique Identifier in Objects")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(dir: &tempfile::TempDir) -> Engine {
        let key = dir.path().join("master");
        std::fs::write(&key, [3; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Engine::new(
            crate::store::Store::open(&dir.path().join("keys.sqlite"), &key).unwrap(),
            false,
        )
    }
    fn request(items: Vec<(u32, Vec<Node>)>, ticket: Option<&Node>) -> Node {
        let mut header = vec![Version(2, 1).node(), Node::int(BATCH_COUNT, 1)];
        if let Some(ticket) = ticket {
            header.push(Node::structure(
                AUTHENTICATION,
                vec![Node::structure(
                    CREDENTIAL,
                    vec![
                        Node::enumeration(CREDENTIAL_TYPE, 6),
                        Node::structure(CREDENTIAL_VALUE, vec![ticket.clone()]),
                    ],
                )],
            ));
        }
        let mut message = vec![Node::structure(REQUEST_HEADER, header)];
        for (op, p) in items {
            message.push(Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, op),
                    Node::structure(REQUEST_PAYLOAD, p),
                ],
            ));
        }
        Node::structure(REQUEST_MESSAGE, message)
    }
    fn result(response: &Node) -> (u32, Option<Node>) {
        let item = response.get(BATCH_ITEM).unwrap();
        (
            item.get(RESULT_STATUS).unwrap().number().unwrap(),
            item.get(RESPONSE_PAYLOAD)
                .and_then(|p| p.get(TICKET))
                .cloned(),
        )
    }
    fn channel(fingerprint: &str) -> super::channel::Channel {
        super::channel::Channel {
            fingerprint: fingerprint.into(),
            policy_fingerprint: fingerprint.into(),
            certificate: vec![],
            chain: vec![],
        }
    }

    #[test]
    fn revoke_fingerprint_revokes_only_tickets_issued_over_that_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(&dir);
        let login = |engine: &mut Engine, fingerprint: Option<&str>, rights: bool| {
            let (op, p) = if rights {
                (
                    47,
                    vec![Node::structure(
                        RIGHTS,
                        vec![Node::structure(RIGHT, vec![])],
                    )],
                )
            } else {
                (45, vec![])
            };
            let message = request(vec![(op, p)], None);
            let response = match fingerprint {
                Some(f) => engine.with_channel(&channel(f), |e| e.process("alice", &message)),
                None => engine.process("alice", &message),
            };
            result(&response.unwrap()).1.unwrap()
        };
        let from_f = login(&mut engine, Some("ff"), false);
        let delegated_from_f = login(&mut engine, Some("ff"), true);
        let from_g = login(&mut engine, Some("aa"), false);
        let in_process = login(&mut engine, None, false);
        engine.tickets.revoke_fingerprint("ff");
        let query = vec![(24, vec![])];
        let works = |engine: &mut Engine, ticket: &Node, owner: &str| {
            let response = engine
                .process(owner, &request(query.clone(), Some(ticket)))
                .unwrap();
            result(&response).0 == 0
        };
        assert!(!works(&mut engine, &from_f, "alice"));
        assert!(!works(&mut engine, &delegated_from_f, "bob"));
        assert!(works(&mut engine, &from_g, "alice"));
        assert!(works(&mut engine, &in_process, "alice"));
    }

    #[test]
    fn budgets_are_shared_by_every_snapshot() {
        let budget = Arc::new(AtomicU64::new(1));
        let snapshot = budget.clone();
        assert!(charge(&budget));
        assert!(!charge(&snapshot));
        assert!(!charge(&budget));
    }
}
