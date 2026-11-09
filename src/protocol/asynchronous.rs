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

//! Asynchronous processing for KMIP 1.0-2.1 and draft 3.0: deferred batches,
//! Poll, Cancel and, from 2.1, Process and Query Asynchronous Requests.
//!
//! A deferred request is answered at once with Result Status Operation
//! Pending and one server-random Asynchronous Correlation Value per batch item
//! (2.1 table 399: "REQUIRED if Result Status is Pending"). The whole message is
//! queued and later runs exactly as a synchronous message would, with its batch
//! order, error continuation option, ID Placeholder and the principal's
//! operation policy and object grants captured at submission. Each item's
//! final Batch Item is then kept for Poll, which returns it with Operation Poll
//! (2.1 section 6.1.38: "identical to the response that would have been sent
//! if the operation had completed synchronously").
//!
//! When the server defers (KMIP 1.x sections 6.8/7.2 and 2.x section 9.1: "the
//! server decides which operations are performed synchronously or
//! asynchronously"):
//! * 2.0/2.1 Mandatory: always ("SHALL process all batch items in the request
//!   asynchronously", 2.1 table 431). A Mandatory batch with Poll, Cancel,
//!   Process or Query Asynchronous Requests is refused with Invalid Field: those
//!   responses "SHALL NOT be asynchronous".
//! * 1.x True and 2.x Optional: only batches containing Create Key Pair or
//!   Re-key Key Pair, the long-running generation operations, and only while
//!   the queue has room. Everything else stays synchronous.
//! * Prohibited, False or absent: never.
//!
//! Draft 3.0 follows the 2.x rules. One request item can yield several
//! results: "If multiple unique identifiers would be referenced then the
//! operation is repeated for each of them as separate batch items" (2.0/2.1
//! section 11.56/11.58, draft 3.0 section 11.60). How many is known only when
//! the batch runs, so the Asynchronous Correlation Value names the request
//! batch item, and Poll of a completed item answers with every result that
//! item produced, as consecutive Poll batch items: the response "SHALL be
//! identical to the response that would have been sent if the operation had
//! completed synchronously" (draft 3.0 section 6.1.45), and a synchronous
//! response repeats the item the same way. Results are matched to request
//! items by the order the engine produced them, not by Unique Batch Item ID,
//! which draft 3.0 removed.
//!
//! The queue is in memory, owner scoped and bounded: at most `MAX_BATCHES`
//! waiting batches, `MAX_PER_OWNER` batches per principal and `MAX_STORED` in
//! all. Results are kept for `RETAIN_SECONDS` after completion, unless room
//! is needed for a new batch: completed batches never refuse a submission;
//! the submitting principal's oldest completed batch is dropped first, then
//! the oldest overall. A dropped result polls as unknown. A queued message
//! keeps no request-header Authentication (no plaintext Password or Ticket
//! is retained); the identity verified at submission is stored instead and
//! re-checked when the batch runs. A restart loses the queue: a request still queued never runs,
//! later Polls fail as unknown and Cancel reports Unavailable. A correlation
//! value is only found by the identity that submitted it (the certificate
//! principal, or under credential identity its verified user or device) with
//! the same protocol version; queue bounds count per certificate principal.
//! Cancel takes effect only before a batch runs; a canceled item
//! fails with Operation Canceled By Requester and the batch's continuation
//! option applies to that failure. Items that a Stop or Undo option left
//! unprocessed are reported to Poll as General Failure, since a synchronous
//! response would have omitted them.
use super::*;
use crate::authorization::ObjectGrant;

pub(super) const MAX_BATCHES: usize = 32;
pub(super) const MAX_PER_OWNER: usize = 8;
pub(super) const MAX_STORED: usize = 4 * MAX_BATCHES;
pub(super) const RETAIN_SECONDS: i64 = 600;
const CORRELATION_BYTES: usize = 16;
const CANCEL: u32 = 25;
const POLL: u32 = 26;
const QUERY_ASYNCHRONOUS_REQUESTS: u32 = 57;
const PROCESS: u32 = 58;
/// Login (45) and Delegated Login (47): a queued run has no TLS channel, so a
/// deferred ticket would carry no issuing certificate (tickets.rs).
const LOGIN: u32 = 45;
const DELEGATED_LOGIN: u32 = 47;
/// Re-Provision (53) replaces the credential of the connection carrying it
/// (provisioning.rs).
const RE_PROVISION: u32 = 53;
/// Operations that are never deferred: responses that cannot themselves be
/// asynchronous, and operations bound to the requesting TLS connection.
const SYNCHRONOUS_ONLY: [u32; 7] = [
    CANCEL,
    POLL,
    QUERY_ASYNCHRONOUS_REQUESTS,
    PROCESS,
    LOGIN,
    DELEGATED_LOGIN,
    RE_PROVISION,
];
/// Operations for which the server chooses asynchronous processing when the
/// client allows it: RSA key pair generation can take seconds.
const LONG_RUNNING: [u32; 2] = [2, 29];
/// Cancellation Result enumeration (1.4 9.1.3.2.25; 2.1 table 438).
const CANCELED: u32 = 1;
const COMPLETED: u32 = 3;
const FAILED: u32 = 4;
const UNAVAILABLE: u32 = 5;
/// Processing Stage enumeration (2.1 table 472).
const SUBMITTED: u32 = 1;
const STAGE_COMPLETED: u32 = 3;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Indicator {
    Prohibited,
    Allowed,
    Mandatory,
}

/// Read the request header Asynchronous Indicator.
pub(super) fn indicator(v: Version, header: &Node) -> R<Indicator> {
    let Some(a) = header.get(ASYNCHRONOUS_INDICATOR) else {
        return Ok(Indicator::Prohibited);
    };
    if v.0 == 1 {
        // KMIP 1.0-1.4 section 6.7: a Boolean saying "whether the client is
        // able to accept an asynchronous response". 1.0 table 187 and 1.1
        // table 207 say a present indicator "SHALL be set to True"; that is a
        // client requirement, so a present False still means synchronous.
        return Ok(if a.flag()? {
            Indicator::Allowed
        } else {
            Indicator::Prohibited
        });
    }
    match a.value {
        // 2.x section 11.3 / draft 3.0 table 539.
        Value::Enumeration(3) => Ok(Indicator::Prohibited),
        Value::Enumeration(2) => Ok(Indicator::Allowed),
        Value::Enumeration(1) => Ok(Indicator::Mandatory),
        _ => Err(fail(7, "Invalid Asynchronous Indicator")),
    }
}

#[derive(Default)]
pub(crate) struct Queue {
    batches: Vec<Batch>,
    /// Cancel, Process and Poll effects, applied when their batch commits.
    pub(super) actions: Vec<Action>,
    /// Cancellation flags of the batch now running, by request item index.
    canceled: Vec<bool>,
    running: bool,
    /// The stored result fields Poll returns for the current item.
    pub(super) poll: Option<Vec<Node>>,
    /// The submission-time identity of the batch now running.
    identity: Option<system::Identity>,
    /// For the batch now running, after it committed: the request item index
    /// of each response batch item, in order.
    origins: Option<Vec<usize>>,
}
struct Batch {
    /// The certificate principal, which runs the batch and is charged for it.
    owner: String,
    /// The identity that may Poll, Cancel, Process or list it.
    scope: String,
    version: Version,
    /// The request without its Authentication header field.
    request: Node,
    /// What the request-header credentials proved at submission.
    identity: Option<system::Identity>,
    allowed: Option<Vec<u32>>,
    grants: Vec<ObjectGrant>,
    /// Microseconds since the epoch (Submission Date is Date Time Extended).
    submitted: i64,
    completed: Option<i64>,
    priority: bool,
    items: Vec<Item>,
}
struct Item {
    correlation: Vec<u8>,
    operation: Option<u32>,
    canceled: bool,
    obtained: bool,
    /// The final Batch Items of this request item (several when its
    /// identifier expanded), without Operation and Unique Batch Item ID.
    result: Option<Vec<Vec<Node>>>,
}
#[derive(Clone)]
pub(crate) enum Action {
    Cancel(String, Vec<u8>),
    Process(String, Vec<u8>),
    Obtained(String, Vec<u8>),
}

fn micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as i64)
}

impl Queue {
    fn purge(&mut self) {
        let cutoff = now() - RETAIN_SECONDS;
        self.batches
            .retain(|b| b.completed.is_none_or(|done| done >= cutoff));
    }
    fn find(&self, scope: &str, v: Version, correlation: &[u8]) -> Option<(usize, usize)> {
        self.batches.iter().enumerate().find_map(|(b, batch)| {
            (batch.scope == scope && batch.version == v)
                .then(|| {
                    batch
                        .items
                        .iter()
                        .position(|item| item.correlation == correlation)
                })
                .flatten()
                .map(|i| (b, i))
        })
    }
    fn item_mut(&mut self, scope: &str, correlation: &[u8]) -> Option<(&mut Batch, usize)> {
        let batch = self
            .batches
            .iter_mut()
            .find(|b| b.scope == scope && b.items.iter().any(|i| i.correlation == correlation))?;
        let index = batch
            .items
            .iter()
            .position(|i| i.correlation == correlation)?;
        Some((batch, index))
    }
    pub(super) fn apply(&mut self) {
        for action in std::mem::take(&mut self.actions) {
            match action {
                Action::Cancel(owner, value) => {
                    if let Some((batch, i)) = self.item_mut(&owner, &value)
                        && batch.completed.is_none()
                    {
                        batch.items[i].canceled = true;
                        batch.items[i].obtained = true;
                    }
                }
                Action::Process(owner, value) => {
                    if let Some((batch, _)) = self.item_mut(&owner, &value)
                        && batch.completed.is_none()
                    {
                        batch.priority = true;
                    }
                }
                Action::Obtained(owner, value) => {
                    if let Some((batch, i)) = self.item_mut(&owner, &value) {
                        batch.items[i].obtained = true;
                    }
                }
            }
        }
    }
    /// The batch item index is canceled in the batch now running.
    pub(super) fn canceled(&self, index: usize) -> bool {
        self.canceled.get(index).copied().unwrap_or(false)
    }
    /// Record the response order of the batch now running once it committed.
    pub(super) fn finished(&mut self, origins: Vec<usize>) {
        if self.running {
            self.origins = Some(origins);
        }
    }
    pub fn pending(&self) -> bool {
        self.batches.iter().any(|b| b.completed.is_none())
    }
    /// While a queued batch runs: the identity verified at its submission
    /// (`Some(None)` without credentials). None for an ordinary request.
    pub(super) fn submitted_identity(&mut self) -> Option<Option<system::Identity>> {
        self.running.then(|| self.identity.take())
    }
    /// Make room for one more batch of `owner`. Waiting batches are never
    /// dropped; completed ones are, the owner's own oldest first.
    fn admit(&mut self, owner: &str) -> bool {
        let waiting = |b: &Batch| b.completed.is_none();
        if self.batches.iter().filter(|b| waiting(b)).count() >= MAX_BATCHES
            || self
                .batches
                .iter()
                .filter(|b| b.owner == owner && waiting(b))
                .count()
                >= MAX_PER_OWNER
        {
            return false;
        }
        let oldest = |batches: &[Batch], own: bool| {
            batches
                .iter()
                .enumerate()
                .filter(|(_, b)| b.completed.is_some() && (!own || b.owner == owner))
                .min_by_key(|(_, b)| b.completed)
                .map(|(i, _)| i)
        };
        while self.batches.iter().filter(|b| b.owner == owner).count() >= MAX_PER_OWNER {
            let Some(i) = oldest(&self.batches, true) else {
                return false;
            };
            self.batches.remove(i);
        }
        while self.batches.len() >= MAX_STORED {
            let Some(i) = oldest(&self.batches, false) else {
                return false;
            };
            self.batches.remove(i);
        }
        true
    }
}

fn correlation_value(p: &Node) -> R<Vec<u8>> {
    no_fields(p, &[ASYNCHRONOUS_CORRELATION_VALUE])?;
    Ok(p.required(ASYNCHRONOUS_CORRELATION_VALUE)?
        .byte_string()?
        .to_vec())
}
/// Server-internal Poll payload field naming which stored result of an
/// expanded item to return. `prepare_poll` adds it after validating the
/// client payload, so a client cannot supply it.
const RESULT_INDEX: u32 = 0x54ff_ff01;
/// A list structure whose children all have `tag` ("zero or more").
fn only(n: &Node, tag: u32) -> R<()> {
    if n.children()?.iter().any(|c| c.tag != tag) {
        return Err(fail(8, "Request contains an unsupported field"));
    }
    Ok(())
}
fn unknown(v: Version) -> Failure {
    // 1.4 table 352: Item Not Found; 2.x: Invalid Asynchronous Correlation Value.
    fail(
        if v.0 >= 2 { 0x2b } else { 1 },
        "No outstanding asynchronous operation has this correlation value",
    )
}
fn result_fields(item: &Node) -> Vec<Node> {
    item.children()
        .map(|fields| {
            fields
                .iter()
                .filter(|n| ![OPERATION, UNIQUE_BATCH_ITEM_ID].contains(&n.tag))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}
/// Result Status of a stored result; Stop and Undo treat a polled failure
/// as a failure of the Poll item.
pub(super) fn status(fields: &[Node]) -> u32 {
    fields
        .iter()
        .find(|n| n.tag == RESULT_STATUS)
        .and_then(|n| n.number().ok())
        .unwrap_or(1)
}

impl Engine {
    /// Defer a validated message when the indicator and server policy call for
    /// it. Returns the immediate Operation Pending response.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn defer(
        &mut self,
        owner: &str,
        v: Version,
        request: &Node,
        items: &[&Node],
        mode: Indicator,
        allowed: Option<&[u32]>,
        client_correlation: Option<&Node>,
        limit: Budget,
        wire: &Wire,
    ) -> R<Option<Node>> {
        if mode == Indicator::Prohibited || self.side.queue.running {
            return Ok(None);
        }
        let operations = items
            .iter()
            .map(|item| item.get(OPERATION).and_then(|n| n.number().ok()))
            .collect::<Vec<_>>();
        let synchronous_only = operations
            .iter()
            .any(|op| op.is_some_and(|op| SYNCHRONOUS_ONLY.contains(&op)));
        // A message authenticated by a delegated ticket never reaches the
        // queue: the queue is scoped by owner, which would be the delegator's
        // (tickets.rs).
        let delegated = self
            .authorization
            .identity
            .as_ref()
            .is_some_and(|i| i.is_delegated());
        if mode == Indicator::Mandatory && (synchronous_only || delegated) {
            return Err(fail(7, "This request cannot be processed asynchronously"));
        }
        if delegated {
            return Ok(None);
        }
        if mode == Indicator::Allowed
            && (synchronous_only
                || !operations
                    .iter()
                    .any(|op| op.is_some_and(|op| LONG_RUNNING.contains(&op))))
        {
            return Ok(None);
        }
        // Poll, Cancel, Process and listing are for the submitting identity.
        let scope = self
            .request_owner(owner)
            .unwrap_or_else(|| owner.to_owned());
        let queue = &mut self.side.queue;
        queue.purge();
        // The stored copy drops the Asynchronous Indicator and the
        // Authentication (its Password or Ticket value): the verified
        // identity is kept instead.
        let mut stored = request.clone();
        if let Value::Structure(message) = &mut stored.value
            && let Some(header) = message.iter_mut().find(|n| n.tag == REQUEST_HEADER)
            && let Value::Structure(fields) = &mut header.value
        {
            fields.retain(|n| n.tag != ASYNCHRONOUS_INDICATOR && n.tag != AUTHENTICATION);
        }
        let mut entries = vec![];
        let mut response = vec![];
        for (item, operation) in items.iter().zip(&operations) {
            let correlation = crypto::random(CORRELATION_BYTES)
                .map_err(|_| fail(0x100, "Random source failed"))?
                .to_vec();
            let mut fields = vec![];
            if let Some(op) = operation {
                fields.push(Node::enumeration(OPERATION, *op));
            }
            if let Some(id) = item.get(UNIQUE_BATCH_ITEM_ID) {
                fields.push(id.clone());
            }
            fields.push(Node::enumeration(RESULT_STATUS, 2));
            fields.push(Node::bytes(
                ASYNCHRONOUS_CORRELATION_VALUE,
                correlation.clone(),
            ));
            response.push(Node::structure(BATCH_ITEM, fields));
            entries.push(Item {
                correlation,
                operation: *operation,
                canceled: false,
                obtained: false,
                result: None,
            });
        }
        let mut message = vec![with_server_proof(
            response_header(v, items.len(), client_correlation),
            self.authorization.server_hashed_password.as_ref(),
        )];
        message.extend(response);
        let message = Node::structure(RESPONSE_MESSAGE, message);
        if !wire.measure(&message).is_ok_and(|size| size.fits(limit)) {
            return if mode == Indicator::Mandatory {
                Err(response_too_large())
            } else {
                Ok(None)
            };
        }
        if !queue.admit(owner) {
            return if mode == Indicator::Mandatory {
                Err(server_limit(v, "Asynchronous request queue is full"))
            } else {
                Ok(None)
            };
        }
        queue.batches.push(Batch {
            owner: owner.to_owned(),
            scope,
            version: v,
            request: stored,
            identity: self.authorization.identity.clone(),
            allowed: allowed.map(<[u32]>::to_vec),
            grants: self.authorization.grants.clone(),
            submitted: micros(),
            completed: None,
            priority: false,
            items: entries,
        });
        Ok(Some(message))
    }

    /// Run one queued batch, prioritized first. Returns whether one ran.
    pub fn run_asynchronous(&mut self) -> bool {
        let _fips = crate::fips::enter(self.fips);
        let _curves = crate::crypto::ec::enter(self.ec_curves);
        let queue = &mut self.side.queue;
        queue.purge();
        if queue.running {
            return false;
        }
        let Some(index) = queue
            .batches
            .iter()
            .position(|b| b.completed.is_none() && b.priority)
            .or_else(|| queue.batches.iter().position(|b| b.completed.is_none()))
        else {
            return false;
        };
        let batch = &queue.batches[index];
        let (owner, request, allowed, grants) = (
            batch.owner.clone(),
            batch.request.clone(),
            batch.allowed.clone(),
            batch.grants.clone(),
        );
        queue.canceled = batch.items.iter().map(|i| i.canceled).collect();
        queue.identity = batch.identity.clone();
        queue.origins = None;
        queue.running = true;
        let len = |n: &Node| Ok(n.encoded_len());
        let mut check = |_: &Node| Ok(());
        let mut wire = Wire {
            check: &mut check,
            len: &len,
            frame: crate::ttlv::MAX_FRAME,
        };
        // A queued batch never acts on the connection that happens to be
        // processing a request now (channel.rs).
        let channel = self.channel.take();
        let result = self.process_wire(&owner, &request, allowed.as_deref(), &grants, &mut wire);
        self.channel = channel;
        let queue = &mut self.side.queue;
        queue.running = false;
        queue.identity = None;
        queue.canceled.clear();
        let origins = queue.origins.take();
        let Some(batch) = queue.batches.get_mut(index) else {
            return true;
        };
        let request_items = request.all(BATCH_ITEM).collect::<Vec<_>>();
        let failure = |item: &Node, e: &Failure| {
            let op = item
                .get(OPERATION)
                .and_then(|n| n.number().ok())
                .unwrap_or(0);
            result_fields(&failure_item(op, None, e, true))
        };
        let mut results: Vec<Option<Vec<Vec<Node>>>> = vec![None; batch.items.len()];
        match &result {
            Ok(response) => {
                let responses = response.all(BATCH_ITEM).collect::<Vec<_>>();
                match origins {
                    // A committed batch: each result belongs to the request
                    // item that produced it, several for an expanded item.
                    Some(origins) if origins.len() == responses.len() => {
                        for (item, origin) in responses.iter().zip(origins) {
                            if let Some(slot) = results.get_mut(origin) {
                                slot.get_or_insert_with(Vec::new).push(result_fields(item));
                            }
                        }
                    }
                    // A message-level failure answers every item.
                    _ => {
                        let fields = responses
                            .iter()
                            .map(|item| result_fields(item))
                            .collect::<Vec<_>>();
                        if !fields.is_empty() {
                            results.fill(Some(fields));
                        }
                    }
                }
            }
            Err(e) => {
                for (slot, item) in results.iter_mut().zip(&request_items) {
                    *slot = Some(vec![failure(item, e)]);
                }
            }
        }
        let skipped = fail(
            0x100,
            "Not processed: an earlier batch item failed under Stop or Undo",
        );
        for ((entry, slot), item) in batch.items.iter_mut().zip(results).zip(&request_items) {
            entry.result = Some(slot.unwrap_or_else(|| vec![failure(item, &skipped)]));
        }
        batch.completed = Some(now());
        batch.priority = false;
        true
    }

    /// Run batches that Process asked for before this response is returned,
    /// so the next Poll does not report Pending (2.1 section 6.1.39).
    pub(super) fn run_prioritized(&mut self) {
        while !self.side.queue.running
            && self
                .side
                .queue
                .batches
                .iter()
                .any(|b| b.completed.is_none() && b.priority)
        {
            if !self.run_asynchronous() {
                break;
            }
        }
    }

    /// Expand a Poll item into one item per stored result of the polled
    /// request item (more than one when its identifier expanded), so each
    /// result is sized and reported as its own Poll batch item.
    pub(super) fn prepare_poll(&self, owner: &str, v: Version, item: &Node) -> R<Vec<Node>> {
        let value = correlation_value(item.required(REQUEST_PAYLOAD)?)?;
        let count = self
            .side
            .queue
            .find(owner, v, &value)
            .and_then(|(b, i)| self.side.queue.batches[b].items[i].result.as_ref())
            .map_or(1, Vec::len)
            .max(1);
        if count > 128 {
            return Err(server_limit(v, "Expanded batch exceeds the server limit"));
        }
        Ok((0..count)
            .map(|index| {
                let mut item = item.clone();
                if let Value::Structure(fields) = &mut item.value
                    && let Some(payload) = fields.iter_mut().find(|n| n.tag == REQUEST_PAYLOAD)
                    && let Value::Structure(payload) = &mut payload.value
                {
                    payload.push(Node::int(RESULT_INDEX, index as i32));
                }
                item
            })
            .collect())
    }

    pub(super) fn poll(&mut self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        no_fields(p, &[ASYNCHRONOUS_CORRELATION_VALUE, RESULT_INDEX])?;
        let index = number(p, RESULT_INDEX, 0)? as usize;
        let value = p
            .required(ASYNCHRONOUS_CORRELATION_VALUE)?
            .byte_string()?
            .to_vec();
        let queue = &mut self.side.queue;
        queue.purge();
        let (b, i) = queue.find(owner, v, &value).ok_or_else(|| unknown(v))?;
        let item = &queue.batches[b].items[i];
        // Draft 3.0 section 6.1.45: an incomplete operation has "no payload
        // and a Result Status of Pending".
        let fields = match &item.result {
            Some(results) => {
                let fields = results
                    .get(index)
                    .cloned()
                    .ok_or_else(|| fail(0x100, "Asynchronous result changed while polled"))?;
                queue
                    .actions
                    .push(Action::Obtained(owner.to_owned(), value.clone()));
                fields
            }
            None => vec![
                Node::enumeration(RESULT_STATUS, 2),
                Node::bytes(ASYNCHRONOUS_CORRELATION_VALUE, value),
            ],
        };
        queue.poll = Some(fields);
        Ok(vec![])
    }

    pub(super) fn cancel(&mut self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        let value = correlation_value(p)?;
        let queue = &mut self.side.queue;
        queue.purge();
        let result = match queue.find(owner, v, &value) {
            None => UNAVAILABLE,
            Some((b, i)) => {
                let item = &queue.batches[b].items[i];
                let result = match &item.result {
                    None => CANCELED,
                    Some(_) if item.canceled => CANCELED,
                    Some(results) if results.iter().all(|fields| status(fields) == 0) => COMPLETED,
                    Some(_) => FAILED,
                };
                queue.actions.push(if item.result.is_none() {
                    Action::Cancel(owner.to_owned(), value.clone())
                } else {
                    Action::Obtained(owner.to_owned(), value.clone())
                });
                result
            }
        };
        Ok(vec![
            Node::bytes(ASYNCHRONOUS_CORRELATION_VALUE, value),
            Node::enumeration(CANCELLATION_RESULT, result),
        ])
    }

    pub(super) fn process_asynchronous(
        &mut self,
        owner: &str,
        v: Version,
        p: &Node,
    ) -> R<Vec<Node>> {
        let value = correlation_value(p)?;
        let queue = &mut self.side.queue;
        queue.purge();
        let (b, _) = queue.find(owner, v, &value).ok_or_else(|| unknown(v))?;
        if queue.batches[b].completed.is_none() {
            queue.actions.push(Action::Process(owner.to_owned(), value));
        }
        Ok(vec![])
    }

    /// 2.1 section 6.1.41: report requests "for which results have not yet
    /// been obtained via the normal Poll (or less-normal Cancel) operation".
    pub(super) fn query_asynchronous(&mut self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        no_fields(p, &[ASYNCHRONOUS_CORRELATION_VALUES, OPERATIONS])?;
        let values = match p.get(ASYNCHRONOUS_CORRELATION_VALUES) {
            Some(n) => {
                only(n, ASYNCHRONOUS_CORRELATION_VALUE)?;
                Some(
                    n.all(ASYNCHRONOUS_CORRELATION_VALUE)
                        .map(|n| n.byte_string().map(<[u8]>::to_vec))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            None => None,
        };
        let operations = match p.get(OPERATIONS) {
            Some(n) => {
                only(n, OPERATION)?;
                Some(
                    n.all(OPERATION)
                        .map(Node::number)
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
            None => None,
        };
        let queue = &mut self.side.queue;
        queue.purge();
        let mut out = vec![];
        for batch in queue
            .batches
            .iter()
            .filter(|b| b.scope == owner && b.version == v)
        {
            for item in batch.items.iter().filter(|i| !i.obtained) {
                let Some(op) = item.operation else { continue };
                if values
                    .as_ref()
                    .is_some_and(|w| !w.contains(&item.correlation))
                    || operations.as_ref().is_some_and(|w| !w.contains(&op))
                {
                    continue;
                }
                out.push(Node::structure(
                    ASYNCHRONOUS_REQUEST,
                    vec![
                        Node::bytes(ASYNCHRONOUS_CORRELATION_VALUE, item.correlation.clone()),
                        Node::enumeration(OPERATION, op),
                        Node {
                            tag: SUBMISSION_DATE,
                            value: Value::DateTimeExtended(batch.submitted),
                        },
                        Node::enumeration(
                            PROCESSING_STAGE,
                            if item.result.is_some() {
                                STAGE_COMPLETED
                            } else {
                                SUBMITTED
                            },
                        ),
                    ],
                ));
            }
        }
        Ok(out)
    }
}
